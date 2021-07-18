#!/usr/bin/env python3

# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Sajjad "JJ" Arshad (sajjadium)

from os.path import join
import json
import os
import random
import shlex
import string
import subprocess
import sys
import time
import base64

ADB_PORT = int(random.random() * 60000 + 5000)
EMULATOR_PORT = ADB_PORT + 1
EXPLOIT_TIME_SECS = 30
APK_FILE = "/challenge/app.apk"
FLAG_FILE = "/challenge/flag"
HOME = "/home/user"

ENV = {}
ENV.update(os.environ)
ENV.update({
    "ANDROID_ADB_SERVER_PORT": "{}".format(ADB_PORT),
    "ANDROID_SERIAL": "emulator-{}".format(EMULATOR_PORT),
    "ANDROID_SDK_ROOT": "/opt/android/sdk",
    "ANDROID_SDK_HOME": HOME,
    "ANDROID_PREFS_ROOT": HOME,
    "ANDROID_EMULATOR_HOME": HOME + "/.android",
    "ANDROID_AVD_HOME": HOME + "/.android/avd",
    "JAVA_HOME": "/usr/lib/jvm/java-11-openjdk-amd64",
    "PATH": "/opt/android/sdk/cmdline-tools/latest/bin:/opt/android/sdk/emulator:/opt/android/sdk/platform-tools:/bin:/usr/bin:" + os.environ.get("PATH", "")
})

def print_to_user(message):
    print(message)
    sys.stdout.flush()

def setup_emulator():
    subprocess.call(
        "avdmanager" +
        " create avd" +
        " --name 'pixel_4_xl_api_30'" +
        " --abi 'google_apis/x86_64'" +
        " --package 'system-images;android-30;google_apis;x86_64'" +
        " --device pixel_4_xl" +
        " --force" +
        " > /dev/null 2> /dev/null",
        env=ENV,
        close_fds=True,
        shell=True)

    return subprocess.Popen(
        "emulator" +
        " -avd pixel_4_xl_api_30" +
        " -no-cache" +
        " -no-snapstorage" +
        " -no-snapshot-save" +
        " -no-snapshot-load" +
        " -no-audio" +
        " -no-window" +
        " -no-snapshot" +
        " -no-boot-anim" +
        " -wipe-data" +
        " -accel on" +
        " -netdelay none" +
        " -no-sim" +
        " -netspeed full" +
        " -delay-adb" +
        " -port {}".format(EMULATOR_PORT) +
        " > /dev/null 2> /dev/null ",
        env=ENV,
        close_fds=True,
        shell=True)

def adb(args, capture_output=True):
    return subprocess.run(
        "adb {} 2> /dev/null".format(" ".join(args)),
        env=ENV,
        shell=True,
        close_fds=True,
        capture_output=capture_output).stdout

def adb_install(apk):
    adb(["install", "-r", apk])

def adb_activity(activity):
    adb(["shell", "am", "start", "-W", "-n", activity])

def adb_logs():
    logs = adb(["logcat", "-d", "-s", "TriDroid"], True)
    for log in logs.decode("utf-8").strip().split("\n"):
        print_to_user(log)

def adb_broadcast(action, extras=None):
    args = ["shell", "am", "broadcast", "-a", action]
    if extras:
        for key in extras:
            args += ["-e", key, extras[key]]
    adb(args)

print_to_user("""
Welcome to TriDroid, the Triangle of Android:

                    /\\
      DEX          /  \\       Web
 (Java & Kotlin)  /    \\  (HTML & JS)
                 /      \\
                /________\\

             Native (C & C++)
""")

print_to_user("Preparing TriDroid. This may take a while ...\n")

emulator = setup_emulator()

adb(["wait-for-device"])

adb_install(APK_FILE)

adb_activity("com.google.ctf.pwn.tridroid/.MainActivity")

with open(FLAG_FILE, "r") as f:
    adb_broadcast("com.google.ctf.pwn.tridroid.SET_FLAG", extras = {
        "data": base64.b64encode(f.read().encode()).decode()
    })

print_to_user("Please enter your name encoded in base64:")

name = sys.stdin.readline().strip()
adb_broadcast("com.google.ctf.pwn.tridroid.SET_NAME", extras = {
    "data": name
})

print_to_user("Thank you! Check out the logs. This may take a while ...\n")

time.sleep(EXPLOIT_TIME_SECS)

adb_logs()

emulator.kill()

