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


import os
import shutil
import subprocess
import sys
import json

def socket_print(string):
    print("=====", string, flush=True)


def get_user_input():
    socket_print("Enter partial source for edge compute app (EOF to finish):")
    user_input = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line == "EOF":
            break
        user_input.append(line)
    socket_print("Input accepted!")
    return user_input


def write_to_rs(contents):
    socket_print("Writing source to disk...")
    rs_prelude = """#![no_std]
    use proc_sandbox::sandbox;

    #[sandbox]
    pub mod user {
        // BEGIN PLAYER REPLACEABLE SECTION
    """.splitlines()

    with open('/home/user/sources/user-0/src/lib.rs', 'w') as fd:
        fd.write('\n'.join(rs_prelude))
        fd.write('\n'.join(contents))
        fd.write("\n}\n")

def check_user_input():
    socket_print("Validating user input before compiling...")
    result = subprocess.run("/home/user/rustup/toolchains/nightly-2020-10-08-x86_64-unknown-linux-gnu/bin/rustc user-0/src/lib.rs -Zast-json=yes", cwd="/home/user/sources", shell=True, timeout=150, capture_output=True)
    try:
        ast = json.loads(result.stdout)
        if len(ast["module"]["items"]) != 5:
            socket_print("Module escaping detected, aborting.")
            sys.exit(1)

    except json.JSONDecodeError:
        socket_print("Something went wrong during validation -- is your input malformed?")
        sys.exit(1)

def build_challenge():
    socket_print("Building edge compute app...")
    shutil.copytree("/home/user/build-cache", "/tmp/chal-build")
    # `rustc --version` == "rustc 1.47.0"
    result = subprocess.run("PATH=/usr/bin:$PATH LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu/ CARGO_TARGET_DIR=/tmp/chal-build /usr/bin/cargo build --frozen --offline", cwd="/home/user/sources", shell=True, timeout=150)
    if result.returncode:
        socket_print("non-zero return code on compilation: " + str(result.returncode))
        sys.exit(1)
    socket_print("Build complete!")


def run_challenge():
    socket_print("Testing edge compute app...")
    result = subprocess.run("/tmp/chal-build/debug/server", shell=True, timeout=10)
    socket_print("Test complete!")


def main():
    user_input = get_user_input()
    write_to_rs(user_input)
    build_challenge()

    # Check user input after building since the compilation in check_user_input() will
    # generate errors after generating the ast since the compilation command is
    # incomplete. Let the proper build run first so users can be presented with any
    # compilation issues, then validate it before we actually run.
    check_user_input()

    run_challenge()


if __name__ == "__main__":
    main()
