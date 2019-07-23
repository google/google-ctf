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

SDCC ?= /usr/bin/sdcc
MAKEBIN ?= /usr/bin/makebin
SDCCFLAGS =

ifdef SIMPLE_SCAN
	SDCCFLAGS += -DSIMPLE_SCAN
endif

ifdef CONTINOUS_RAW_SCAN
	SDCCFLAGS += -DCONTINOUS_RAW_SCAN
endif

ifdef RANDOM_ACCESS_RAW_SCAN
	SDCCFLAGS += -DRANDOM_ACCESS_RAW_SCAN
endif

ifdef SECURE_AND_SCAN
	SDCCFLAGS += -DSECURE_AND_SCAN
endif

.phony: all clean

all: exploit.8051

clean:
	rm -rf *.asm *.hex *.ihx *.8051 *.lk *.lst *.map *.mem *.rel *.rst *.sym

exploit.8051: exploit.ihx
	$(MAKEBIN) $^ > $@

exploit.ihx: exploit.c
	$(SDCC) $^ $(SDCCFLAGS)
