# Copyright 2020 Google LLC
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
#
# This generates a docker image that can be used by the players to locally
# experiment with the challenge

TOOLPREFIX = riscv64-unknown-elf-
CC = $(TOOLPREFIX)gcc
AS = $(TOOLPREFIX)gas
LD = $(TOOLPREFIX)ld
OBJCOPY = $(TOOLPREFIX)objcopy
OBJDUMP = $(TOOLPREFIX)objdump

CFLAGS = -Wall -Werror -fomit-frame-pointer -ggdb
CFLAGS += -MD
CFLAGS += -mcmodel=medany
CFLAGS += -ffreestanding -fno-common -nostdlib -mno-relax
CFLAGS += $(shell $(CC) -fno-stack-protector -E -x c /dev/null >/dev/null 2>&1 && echo -fno-stack-protector)
CFLAGS = -fpie -pie -Os

packet: guest device.h driver.c protocol.h protocol.c
	@echo cd /tmp
	@echo "cat << EOF | base64 -d | gunzip - | tar x"
	@tar c --dereference guest device.h driver.c protocol.h protocol.c | gzip -9 | base64 -w 190
	@echo "EOF"
	@echo "cp ~/driver/Makefile .; make clean; make; insmod main.ko; mknod /dev/pcivault c 246 0; ./guest 1000000"

_%: %.o $(ULIB)
	$(LD) $(LDFLAGS) -N -e main -Ttext 0 -o $@ $^

%.strip: _%
	cp $^ $@
	$(TOOLPREFIX)strip --strip-all $@

%.raw: %.strip
	./extract_raw.sh $^ $@

shellcode_second_stage.h: shellcode_second_stage.raw
	xxd -i $^ > $@

shellcode.h: shellcode.raw
	xxd -i $^ > $@

guest: guest.c shellcode.h shellcode_second_stage.h
	gcc guest.c -Os -o guest
	strip --strip-all ./guest
	patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 ./guest

guest.p: guest
	tar c guest | gzip -9 | base64 -w 190

clean:
	rm -rf guest shellcode.raw shellcode.strip shellcode_second_stage.raw shellcode_second_stage.strip shellcode.d shellcode_second_stage.d _shellcode shellcode.h shellcode_second_stage.h

.PHONY: clean
