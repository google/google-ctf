#!/bin/bash
# Copyright 2018 Google LLC
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
set -xe

# Build RISC-V part of the challenge.
rm -r checker.*.bin || true
riscv64-unknown-elf-gcc -march=rv64imfd -Wall -Wextra -nostdlib -c -o checker.o checker.c -O2
riscv64-unknown-elf-ld checker.o -o checker.riscvelf -e checker -Ttext 0x1000 -Tdata 0x2000
riscv64-unknown-elf-objdump -x checker.riscvelf
python elf_to_flat.py checker.riscvelf
riscv64-unknown-elf-objdump -Mnumeric,no-aliases -d checker.riscvelf

# Test RISC-V emu.
gcc -Wall -Wextra riscv-emu.c -o riscv-emu -DTEST -O2
  #-Wno-unused-function -Wno-unused-variable -Wno-unused-parameter
./riscv-emu

python checker_as_mem.py

gcc -Wall -Wextra riscv-emu.c -o riscv-emu-standalone.o -nostdlib -c -O2 \
    -fno-exceptions -fno-asynchronous-unwind-tables
ld riscv-emu-standalone.o -o riscv-emu-standalone -e rv_checker -Ttext 0x42000000 -z max-page-size=0x1000
objdump -x riscv-emu-standalone
strip riscv-emu-standalone
#checksec --file riscv-emu-standalone

python gen_loader.py
rm loader.pyc || true
python -m compileall loader.py
python gen_risky.py
rm risky.pyc || true
python -m compileall risky.py

echo "Check false"
python risky.py 'wrongflag'

echo "Check true"
python risky.py 'flag{APrettyRiskvTask}'



