#!/usr/bin/env python
#
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import random
import string
import subprocess
import sys
import tempfile
import time

def print_to_user(s):
    print(s)
    sys.stdout.flush()

def is_valid(data):
    if len(payload) > 280:
        print_to_user('Payload is too long! It cannot be longer than 280 bytes.')
        return False
    for b in data:
        if b < 0x20 or 0x80 <= b:
            print_to_user('Invalid character 0x%02x found.' % b)
            return False
    return True

def random_string():
    return ''.join(random.choice(string.ascii_lowercase) for i in range(32))

def run_step(binary_command):
    step_flag = random_string()
    with tempfile.TemporaryDirectory() as working_dir:
        with open("%s/flag" % working_dir, "w") as step_flag_file:
            step_flag_file.write(step_flag)
        result = subprocess.run(
                binary_command,
                input=payload,
                cwd=working_dir,
                capture_output=True)
        return result.stdout.strip() == step_flag.encode('utf8')

print_to_user("""
Please provide a payload that prints the contents of 'flag' and runs on both
x86-64 and arm64v8.

The payload may only contain bytes in the range [0x20, 0x7F] and cannot be
longer than 280 bytes.

Payload:
""".strip())

payload = sys.stdin.buffer.readline().strip()
if not is_valid(payload):
    exit()

ok_x86 = run_step(["/home/user/chal-x86-64"])
ok_arm = run_step(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu", "/home/user/chal-aarch64"])

print_to_user('x86-64 passed:  %s' % ok_x86)
print_to_user('aarch64 passed: %s' % ok_arm)

if ok_x86 and ok_arm:
    with open('/home/user/flag', 'r') as flag_file:
        print_to_user(flag_file.read())
else:
    print_to_user("Sorry, not quite :(")
