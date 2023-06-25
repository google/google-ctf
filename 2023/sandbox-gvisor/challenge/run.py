#!/usr/bin/python3 -u
# Copyright 2023 Google LLC
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

import subprocess
import tempfile
import base64
import sys

with open('/tmp/exploit', 'wb') as f:
    try:
        num_bytes = int(input('How many bytes is your base64-encoded exploit? '))
        if num_bytes > 2**20:
            print('Too big')
            exit(0)
        print('Give me your exploit as base64!', flush=True)
        data = base64.b64decode(sys.stdin.buffer.read(num_bytes))
        f.write(data)
        f.flush()
        print('Let\'s go!', flush=True)
        # For debug info, add '--debug' and '--debug-log=/dev/stdout'
        process = subprocess.Popen(['/home/user/runsc', '--rootless', '--network=none', '--platform=systrap', 'do', '--root=/tmp', '/exploit'],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        outs, errs = process.communicate()
        sys.stdout.buffer.write(outs)
        sys.stdout.buffer.write(errs)
        sys.stdout.flush()
    except Exception as e:
        print(f'Exception: {str(e)}')
