# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import struct
import subprocess

def print_flag(file_name):
    with open("/home/user/%s" % file_name, "r") as f:
        print(f.read().strip())

try:
    size_bytes = sys.stdin.buffer.read(4)
    size = struct.unpack(">I", size_bytes)[0]
    replay_file_bytes = sys.stdin.buffer.read(size)
    assert len(replay_file_bytes) == size, "Unexpected packet length"

    with open("/tmp/recording.inp", "wb") as f:
        f.write(replay_file_bytes)

    retry_count = 0
    while True:
        proc = subprocess.Popen(
            [
                "/usr/games/mame", "genesis", "-cart", "/home/user/sonk.md",
                "-autoboot_script", "/home/user/detect_flag.lua",
                "-input_directory", "/tmp/", "-playback", "recording.inp",
                "-video", "none", "-sound", "none",
                "-speed", "100", "-frameskip", "10", "-seconds_to_run", "300",
            ],
            stdout=subprocess.PIPE)

        output = b""
        exit_code = None
        while True:
            exit_code = proc.poll()
            if exit_code != None:
                break
            output += proc.stdout.read(1)
            if b"Total playback frames" in output:
                proc.kill()
                break

        if exit_code is not None and exit_code != 0:
            # MAME crashed, try again
            retry_count += 1
            if retry_count > 5:
                print("MAME crashed too many times, try again :C")
                break
            continue

        if b"Got flag {A}" in output:
            print_flag("flag_a.txt")
        elif b"Got flag {B}" in output:
            print_flag("flag_b.txt")
        else:
            print("No flag captured in the first 300s of playthrough")
        break
except Exception as e:
    print("Error:", e)
