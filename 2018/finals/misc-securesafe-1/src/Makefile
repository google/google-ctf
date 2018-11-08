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

# Tools
CC = avr-g++
OBJCOPY = avr-objcopy

# Parameters
CFLAGS = -mmcu=atmega168 -DF_CPU=8000000 -flto -Os -std=c++11 # -DWITH_FLAG
# -DWITH_FLAG for release build

# Files
OBJS = main.o md5.o

all: main.bin

%.o: %.cpp
	$(CC) $(CFLAGS) -c $^ -o $@

main.elf: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

%.bin: %.elf
	$(OBJCOPY) -O binary $^ $@

flash: main.bin
	avrdude -c avrisp2 -U flash:w:main.bin -p m168

# http://eleccelerator.com/fusecalc/fusecalc.php?chip=atmega168
fuses:
	avrdude -c avrisp2 -U lfuse:w:0xe2:m -U hfuse:w:0xdf:m -U efuse:w:0xf9:m -p m168

# Set lock bits so that you can't dump the flash
lock:
	avrdude -c avrisp2 -U lock:w:0xC0:m

clean:
	rm -f main.bin main.elf $(OBJS)

.PHONY: clean

