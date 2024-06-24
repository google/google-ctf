# Copyright 2024 Google LLC
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
import dis
import hashlib
import os
import signal
import sys
import time

allowlist = [
    "BINARY_OP",
    "COMPARE_OP",
    "LOAD_CONST",
    "LOAD_NAME",
    "PRINT_EXPR",
    "PUSH_NULL",
    "RESUME",
    "RETURN_VALUE",
    "STORE_NAME",
    "UNARY_NEGATIVE",
]


def check(code):
    for i in dis.get_instructions(code):
        if i.opname not in allowlist:
            print(f"Instruction {i.opname} is not allowed")
            return False

    return True


cache = {}
print("Simple calculator in Python, type 'exit' to exit")
while True:
    sys.stdout.write("\r> ")
    try:
        line = sys.stdin.readline(192).encode("ascii").strip()
    except UnicodeEncodeError as e:
        print(e)
        continue

    if not line or line == b"exit":
        break

    try:
        code = compile(line, "<stdin>", "single")
    except SyntaxError as e:
        print(e)
        continue

    k = hashlib.md5(line).hexdigest()
    if k in cache:
        print(f"Hit code validation result cache with key {k}")
        ok = cache[k]
    else:
        print(f"Caching code validation result with key {k}")
        ok = cache[k] = check(code)

    if ok:
        pid = os.fork()
        if pid:
            t = time.time()
            print("Waiting up to 10s for completion")
            while time.time() < t+10:
              status = os.waitid(os.P_PID, pid, os.WEXITED|os.WNOHANG)
              if status:
                break
              time.sleep(0.1)

            if not status:
              print("Timeout")
              os.kill(pid, signal.SIGKILL)
              os.waitid(os.P_PID, pid, os.WEXITED)
        else:
            try:
                exec(code, {}, {})
            except Exception as e:
                print(e)
            break
    else:
        print("Code validation failed")
