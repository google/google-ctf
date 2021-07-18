#!/usr/bin/env python3
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

import tempfile
import os
import select
import subprocess
import sys

IHEX_LAST_LINE = ':00000001FF'
SIMULATOR_MAX_CYCLES = 1000000

def get_firmware():
    input_firmware = ''
    print("Please upload your firmware in Intel Hex format")
    print(f"The last line should be \"{IHEX_LAST_LINE}\"")
    print("IHex:")
    try:
        for _ in range(1000):
            line = next(sys.stdin).rstrip()
            input_firmware += line + '\n'
            if line == IHEX_LAST_LINE:
                break
        else:
            print("Firmware too large, please try again.")
            return None
    except StopIteration:
        print("Disconnected")
        return None
    return input_firmware

def get_firmware_test():
    with open('firmware.ihx', 'r') as fin:
        firmware = fin.read()
    return firmware

def start_emulator(firmware_file):
    emulator = subprocess.Popen(['./emulator', firmware_file.name, f'{SIMULATOR_MAX_CYCLES}'], bufsize=0)
    return emulator

def main():
    input_firmware = get_firmware()
    #input_firmware = get_firmware_test() # Used for simpler testing
    if not input_firmware:
        return
    print(f"Received {len(input_firmware)} bytes of firmware")

    with tempfile.NamedTemporaryFile(prefix='firmware') as fw_file:
        fw_file.write(input_firmware.encode())
        fw_file.seek(0)
        print("Starting emulator")
        print("Listening for input to send to device:")
        print("Capturing radio transmission from device:")
        emulator = start_emulator(fw_file)
        emulator.wait()

    print("")
    print("Execution completed")

if __name__ == '__main__':
    main()
