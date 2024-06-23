#!/usr/bin/python3

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

import os
import argparse

def write_byte_sequence(filename, size_bytes):
    """Writes a repeating sequence of bytes (00 to FF) to a file."""
    with open(filename, "wb") as f:
        bytes_written = 0
        f.write(b"\xff" * 256)
        while bytes_written < size_bytes:
            for byte_val in range(255):
                f.write(bytes([byte_val]))
                bytes_written += 1
                if bytes_written >= size_bytes:
                    break

if __name__ == "__main__":
    size_bytes = 128 * 1024         # 128 KiB in bytes
    parser=argparse.ArgumentParser(
        description='Generate all max level.')
    parser.add_argument('-o', '--output', type=str)
    args = parser.parse_args()
    write_byte_sequence(args.output, size_bytes)
