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

set -e

echo "++ Generating keys..."
echo "GENERATING KEYS IS COMMENTED OUT"
#python gen.py

echo "++ Compiling payloads for x86 for a sanity check..."

gcc -Wall -Wextra -DTEST arm.c -o test_arm
gcc -Wall -Wextra -DTEST mips.c -o test_mips
gcc -Wall -Wextra -DTEST x86.c -o test_x86
gcc -Wall -Wextra -DTEST ppc.c -o test_ppc
gcc -Wall -Wextra -DTEST sparc.c -o test_sparc
gcc -Wall -Wextra -DTEST s390.c -o test_s390

echo "++ Sanity checking payloads..."
cat keys.backup | grep ARM | sed -e 's/.*: //' | ./test_arm | grep 'journey completed' || (echo "FAIL ARM"; false)
cat keys.backup | grep MIPS | sed -e 's/.*: //' | ./test_mips | grep 'journey completed' || (echo "FAIL MIPS"; false)
cat keys.backup | grep X86 | sed -e 's/.*: //' | ./test_x86 | grep 'journey completed' || (echo "FAIL X86"; false)
cat keys.backup | grep PPC | sed -e 's/.*: //' | ./test_ppc | grep 'journey completed' || (echo "FAIL PPC"; false)
cat keys.backup | grep SPARC | sed -e 's/.*: //' | ./test_sparc | grep 'journey completed' || (echo "FAIL SPARC"; false)
cat keys.backup | grep S390 | sed -e 's/.*: //' | ./test_s390 | grep 'journey completed' || (echo "FAIL S390"; false)

echo "++ Compiling payload for ARM..."
arm-linux-gnueabihf-gcc -Wall -Wextra arm.c -o payload_arm.elf -static -DTEST
#arm-linux-gnueabihf-gcc -c -ffreestanding -Wall -Wextra arm.c -o payload_arm.o -nostdlib
#arm-linux-gnueabihf-ld payload_arm.o -o payload_arm.elf -T arm.lds
#arm-linux-gnueabihf-objcopy -O binary payload_arm.elf payload_arm

echo "++ Compiling payload for X86..."
gcc -Wall -Wextra x86.c -o payload_x86.elf -static -DTEST
#gcc -ffreestanding -Wall -Wextra x86.c -o payload_x86 -nostdlib -Wl,-Tx86.lds

echo "++ Compiling payload for PPC..."
powerpc-linux-gnu-gcc-7 -Wall -Wextra ppc.c -o payload_ppc.elf -static -DTEST
#powerpc-linux-gnu-gcc-7 -ffreestanding -Wall -Wextra ppc.c -o payload_ppc -nostdlib -Wl,-Tppc.lds

echo "++ Compiling payload for MIPS..."
mips-linux-gnu-gcc-7 -Wall -Wextra mips.c -o payload_mips.elf -static -DTEST
#mips-linux-gnu-gcc-7 -c -ffreestanding -Wall -Wextra mips.c -o payload_mips.o -nostdlib
#mips-linux-gnu-ld payload_mips.o -o payload_mips.elf -T mips.lds
#mips-linux-gnu-objcopy -O binary payload_mips.elf payload_mips

echo "++ Compiling payload for SPARC..."
sparc64-linux-gnu-gcc-7 -Wall -Wextra sparc.c -o payload_sparc.elf -static -DTEST
#sparc64-linux-gnu-gcc-7 -DSPARC -c -ffreestanding -Wall -Wextra sparc.c -o payload_sparc.o -nostdlib
#sparc64-linux-gnu-ld payload_sparc.o -o payload_sparc.elf -T sparc.lds
#sparc64-linux-gnu-objcopy -O binary payload_sparc.elf payload_sparc

echo "++ Compiling payload for S390..."
s390x-linux-gnu-gcc-7 -Wall -Wextra s390.c -o payload_s390.elf -DTEST -static
#m68k-linux-gnu-gcc-7 -DM68K -c -ffreestanding -Wall -Wextra m68k.c -o payload_m68k.o -nostdlib
#m68k-linux-gnu-ld payload_m68k.o -o payload_m68k.elf -T m68k.lds
#m68k-linux-gnu-objcopy -O binary payload_m68k.elf payload_m68k

echo "++ Full test..."

python journey.py | grep -q 'CTF{puzzlements}' || (echo "FAIL"; false)

echo "++ Bundling..."

rm -rf journey || true
mkdir -p journey
cp journey.py payload_*.elf journey/
zip -r journey.zip journey/

echo "++ Done."
ls -la journey.zip

