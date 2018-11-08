#!/usr/bin/python
#
# Copyright 2018 Google LLC
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

__author__      = "Ian Eldred Pudney"

# Replaces the placeholder checksum in the binary with the correct checksum.

import sys

version = sys.argv[1]
split_version = [version[i:i+2] for i in range(0, len(version), 2)]
int_version = [int(s, 16) for s in split_version]
bytes_version = [chr(i) for i in int_version]
endian_version = list(reversed(bytes_version))

data = sys.stdin.read()
sys.stdout.write(data.replace("\x78\x56\x34\x12\x78\x56\x34\x12", "".join(endian_version)))
