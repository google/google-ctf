# Copyright 2019 Google LLC
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

VERILATOR ?= /usr/share/verilator

CPPFLAGS += -I. -I$(VERILATOR)/include -Wall -Wextra -faligned-new -fPIC -std=c++1z
SVFLAGS += -Wall -O3 -CFLAGS "-fPIC"

ifdef DEBUG
	SVFLAGS += -DDEBUG=1
endif

.phony: all clean verilated

all: libseeprom.a seeprom_test flagrom firmware.8051

clean:
	$(MAKE) -C firmware clean
	rm -rf *.o seeprom_test libseeprom.a obj_dir emu8051/*.o firmware.8051

verilated.o: $(VERILATOR)/include/verilated.cpp
	$(CXX) -c $(CPPFLAGS) -o $@ $?

libseeprom.a: seeprom.o verilated.o obj_dir/Vseeprom__ALLcls.o obj_dir/Vseeprom__ALLsup.o | verilated
	$(AR) rcs $@ $^

verilated: seeprom.sv
	verilator $(SVFLAGS) --cc seeprom.sv
	$(MAKE) -C obj_dir -f Vseeprom.mk

seeprom.o: verilated

seeprom_test: seeprom_test.o libseeprom.a
	$(CXX) -o $@ $^

firmware.8051: firmware/firmware.c
	$(MAKE) -C firmware
	cp firmware/firmware.8051 .

flagrom: flagrom.o flagrom_i2cm.o libseeprom.a emu8051/emu8051.o
	$(CXX) -o $@ $^ -lssl -lcrypto
