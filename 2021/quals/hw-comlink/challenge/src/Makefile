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

CCFLAGS=-Wall -Wpedantic
SDCCFLAGS=
CC=clang

all: emulator firmware.ihx captured_transmission.dat

debug: CCFLAGS += -DDEBUG -g
debug: SDCCFLAGS += -DDEBUG
debug: emulator firmware.ihx

debug-firmware: SDCCFLAGS += -DDEBUG
debug-firmware: firmware.ihx

verify: captured_transmission.dat
	python3 verify.py

emulator: emulation.c emulator.c ihex_reader.c aes.c aes-mod.c ihex/kk_ihex_read.o Z80/building/obj/release-static/Z80.o
	$(CC) -o emulator $(CCFLAGS) $(CCFLAGS) -Itiny-AES-c -IZ80/API -IZ/API -Iihex Z80/building/obj/release-static/Z80.o ihex/kk_ihex_read.o aes.c aes-mod.c ihex_reader.c emulation.c emulator.c

firmware: firmware.ihx
firmware.ihx: firmware.c
	sdcc -mz80 $(SDCCFLAGS) --data-loc 0x8100 firmware.c

# Dependencies
Z80/building/obj/release-static/Z80.o:
	cd Z80/building; premake4 gmake
	CC=$(CC) CFLAGS="-I../../Z/API" $(MAKE) -C Z80/building/ config=release-static

ihex/kk_ihex_read.o:
	$(MAKE) -C ihex/

aes.c:
	patch -o aes.c tiny-AES-c/aes.c < aes.patch

tiny-AES-c/aes.o:
	$(MAKE) -C tiny-AES-c/

# Test & misc
test: emulator firmware.ihx
	./emulator firmware.ihx 1000000

captured_transmission.dat: emulator firmware.ihx verify.py
	python3 verify.py

dist-test: emulator firmware.ihx captured_transmission.dat
	tar czvf package-test.tgz emulator firmware.ihx captured_transmission.dat run-test.sh

dist: firmware.ihx captured_transmission.dat
	tar czvf challenge.tgz firmware.ihx captured_transmission.dat README.txt

clean:
	rm *.asm *.ihx *.lk *.lst *.map *.noi *.rel *.sym emulator

.PHONY: clean all test debug firmware debug-firmware verify dist-test dist
