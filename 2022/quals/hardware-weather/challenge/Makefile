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
all: firmware.ihex weather

firmware.ihex: firmware.c
	echo Firmware recompilation is commented out to not modify the binary layout.
  #	sdcc firmware.c
  #	packihx firmware.ihx > firmware.hex
  #	srec_cat firmware.hex -intel -Output -Binary > firmware.iram

flagrom.o: flagrom.cc flagrom.h
	g++ -Wall -Wextra -c flagrom.cc

serial.o: serial.cc serial.h
	g++ -Wall -Wextra -c serial.cc

progeeprom.o: progeeprom.cc progeeprom.h
	g++ -Wall -Wextra -c progeeprom.cc

i2cbus.o: i2cbus.cc i2cbus.h
	g++ -Wall -Wextra -c i2cbus.cc

fakei2cdev.o: fakei2cdev.cc fakei2cdev.h
	g++ -Wall -Wextra -c fakei2cdev.cc

weather: weather.cc emu8051/emu8051.cc serial.o flagrom.o progeeprom.o \
         i2cbus.o fakei2cdev.o
	g++ -Wall -Wextra -o weather \
	    weather.cc \
	    flagrom.o \
	    serial.o \
	    progeeprom.o \
	    i2cbus.o \
	    fakei2cdev.o \
	    emu8051/emu8051.cc

