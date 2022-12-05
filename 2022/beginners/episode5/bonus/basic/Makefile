# Copyright 2022 Google LLC
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
all: firmware.ihex basic8051emu

firmware.ihex: firmware.c
	sdcc --xram-loc 0x1000 --xram-size 0x7000 firmware.c
	packihx firmware.ihx > firmware.hex
	srec_cat firmware.hex -intel -Output -Binary > firmware.iram

serial.o: serial.cc serial.h
	g++ -Wall -Wextra -c serial.cc

basic8051emu: basic8051emu.cc emu8051/emu8051.cc serial.o ../third_party/NetSock/NetSock.cpp
	g++ -Wall -Wextra -o basic8051emu \
	    -I ../third_party/NetSock \
	    basic8051emu.cc \
	    serial.o \
	    emu8051/emu8051.cc \
	    ../third_party/NetSock/NetSock.cpp

