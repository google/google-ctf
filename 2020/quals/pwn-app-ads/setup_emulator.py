#!/usr/bin/env python3
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from os.path import join
import json
import os
import random
import shlex
import string
import subprocess
import sys
import time

################################################################################
# Configuration options.

# Set to true to see ADB commands and their output. Should be set to false for
# production.
DEBUG = False

# The amount of time in seconds that players' payloads are allowed to execute
# for before killing the emulator.
EXPLOIT_TIME_SECS = 30

# The number of bits to require for hashcash tokens. This value can be adjusted
# to control rate limiting. A larger value will result in more work / time
# required from the player before accessing the challenge.
RATE_LIMIT_BITS = 28

# A super secret value that can be supplied instead of a hashcash token to
# bypass rate limiting.
SKIP_SECRET = "plz-let-me-in-bud"

# The APK file containing the challenge as a relative path from the current
# working directory.
APK_FILE = "app-release.apk"

# The file containing the flag value as a relative path from the current working
# directory.
FLAG_FILE = "flag.txt"

################################################################################

# Choose a random port for the ADB daemon to listen on. If the default port is
# used, then current instances will attempt to connect to an ADB daemon running
# in another nsjail. This may be torn down early which could lead to strange
# behavior.
ADB_PORT = int(random.random() * 60000 + 5000)
# Choose an explicit port for the emulator to listen on. Since we disable
# network isolation in nsjail, ADB will be able to see all of the emulators. To
# ensure that this script is talking to the emulator that it starts a random and
# explicit port number is used to identify it.
EMULATOR_PORT = ADB_PORT + 1

ENV = {}
ENV.update(os.environ)
ENV.update({
    # Explicitly use the randomly generated ADB and emulator ports to avoid
    # collisions and interactions with other concurrent instances.
    "ANDROID_ADB_SERVER_PORT": "{}".format(ADB_PORT),
    "ANDROID_SERIAL": "emulator-{}".format(EMULATOR_PORT),

    # Paths for the Android emulator and adb.
    "ANDROID_SDK_ROOT": "/opt/android/sdk",
    "ANDROID_SDK_HOME": "/home/user/",
    "ANDROID_EMULATOR_HOME": "/home/user/",
    "ANDROID_AVD_HOME": "/home/user/.android/avd",
    "HOME": "/home/user",
    "PATH": "/opt/android/sdk/cmdline-tools/latest/bin:/opt/android/sdk/emulator:/opt/android/sdk/platform-tools:/usr/bin:" + os.environ.get("PATH", ""),
})

def print_to_user(message):
    """
    Alternative to 'print' that works around output buffering introduced
    by nsjail.
    """
    print(message)
    sys.stdout.flush()

def rate_limit():
    res = "".join(random.choice(string.ascii_lowercase) for i in range(8))
    print_to_user("Provide a token for:")
    print_to_user("  hashcash -mb{} {}".format(RATE_LIMIT_BITS, res))
    stamp = sys.stdin.readline().strip()
    allowed_prefix = "hashcash token: "
    if stamp.find(allowed_prefix) == 0:
        stamp = stamp[len(allowed_prefix):]
    if stamp != SKIP_SECRET:
      if not stamp.startswith("1:"):
        print_to_user("Only hashcash v1 supported")
        exit(1)

def start_emulator():
    subprocess.check_output(
        "avdmanager" +
        " create avd " +
        " --name 'pixel_3a_xl_android_29'" +
        " --abi 'google_apis/x86_64'" +
        " --package 'system-images;android-29;google_apis;x86_64'" +
        " --device pixel_3a_xl " +
        ("" if DEBUG else "> /dev/null 2> /dev/null"),
        shell=True,
        env=ENV)

    return subprocess.Popen(
        ("emulator" +
            "  -avd pixel_3a_xl_android_29 " +
            "  -no-window " +
            "  -no-cache " +
            "  -no-snapstorage " +
            "  -no-snapshot-save " +
            "  -no-snapshot-load " +
            "  -no-audio " +
            "  -no-snapshot " +
            "  -no-boot-anim " +
            "  -wipe-data " +
            "  -netdelay none " +
            "  -no-sim " +
            "  -netspeed full" +
            "  -delay-adb" +
            "  -port {}".format(EMULATOR_PORT) +
            ("" if DEBUG else "> /dev/null 2> /dev/null")
        ),
        env=ENV,
        shell=True)

def adb(args):
    if DEBUG:
        print_to_user("adb: " + " ".join(args))
    return subprocess.check_output(
            ["adb"] + args,
            env=ENV,
            stderr=subprocess.STDOUT)

def adb_install(apk):
    while True:
        try:
            output = adb(["install", "-r", "-d", APK_FILE])
            if DEBUG:
                print_to_user(output)
                print_to_user("\0" * 1024*8)
            if output.find(b"Success") != -1:
                return
        except:
            pass
        time.sleep(5)

def adb_activity(activity):
    while True:
        try:
            output = adb(["shell", "am", "start", activity])
            if output.find(b"Error") == -1:
                return
        except:
            pass
        time.sleep(5)

def adb_broadcast(action, uri=None, extras=None):
    args = ["shell", "am", "broadcast", "-a", action]
    if uri:
        args += ["-d", uri]
    if extras:
        for key in extras:
            args += ["-e", key, extras[key]]
    adb(args)

with open(FLAG_FILE, "r") as f:
    flag = f.read()

print_to_user("""
Check out our new super secure ad framework! We're so confident in it that we
are using it to monetize our login page.

The flag is in the password field, can you read it?

Access to this challenge is rate limited via hashcash so we recommend getting
this working locally before attempting it for real.

To test an ad locally with adb, run:

    $ adb shell am broadcast \\
            -a com.example.app.LOAD_AD \\
            -d http://example.com/your/ad.html

Do you have an ad you want to try out? [y/N]""")
ready = input()
if not (len(ready) > 0 and (ready[0] == "Y" or ready[0] == "y")):
    exit(1)

rate_limit()

print_to_user("Please wait while we find a user for your ad.")
print_to_user("This may take several minutes...")

emulator = start_emulator()
adb(["wait-for-device"])
adb_install(APK_FILE)

adb_activity("com.example.app/.MainActivity")

# Wait for the activity to actually come up.
time.sleep(5)

adb_broadcast("com.example.app.SET_FIELDS", extras={
        "user": "hacker4",
        "pass": flag,
    })

print_to_user("Please provide a URL:")
url = input()
adb_broadcast("com.example.app.LOAD_AD", uri=shlex.quote(url))

print_to_user("Thank you! Please wait while we run your ad...")

time.sleep(EXPLOIT_TIME_SECS)
emulator.kill()

print_to_user("All done!")
