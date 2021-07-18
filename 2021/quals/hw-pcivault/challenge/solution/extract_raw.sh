#!/usr/bin/env bash

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

CNT=$(riscv64-unknown-elf-objdump -x $1 | grep memsz | cut -d 'm' -f 3 | cut -d 'x' -f2 | cut -d ' ' -f 1)
CNT=$(printf '%d' 0x$CNT)

OFF=$(riscv64-unknown-elf-objdump -x $1 | grep off | cut -d 'x' -f 2 | cut -d ' ' -f 1)
OFF=$(printf '%d' 0x$OFF)

dd if=$1 skip=$OFF bs=1 count=$CNT of=$2

echo "Offset $OFF Count $CNT"
