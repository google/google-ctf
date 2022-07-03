# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
BINARY = firmware

FP_FLAGS   ?= -msoft-float
ARCH_FLAGS  = -mthumb -mcpu=cortex-m0 $(FP_FLAGS)

PREFIX     ?= arm-none-eabi
CC         := $(PREFIX)-gcc
LD         := $(PREFIX)-gcc
OBJCOPY    := $(PREFIX)-objcopy
OBJDUMP    := $(PREFIX)-objdump

# Source files
LDSCRIPT    = $(BINARY).ld
OBJS       += main.o aes.o elmoasmfunctions.o

# C flags
CFLAGS += -Os -g
CFLAGS += -Wextra -Wshadow -Wimplicit-function-declaration
CFLAGS += -Wredundant-decls -Wmissing-prototypes -Wstrict-prototypes
CFLAGS += -fno-common -ffunction-sections -fdata-sections

# C & C++ preprocessor common flags
CPPFLAGS  += -MD
CPPFLAGS  += -Wall -Wundef

# Linker flags
LDFLAGS   += --static -nostartfiles
LDFLAGS   += -T$(LDSCRIPT)
LDFLAGS   += -Wl,-Map=$(*).map
LDFLAGS   += -Wl,--gc-sections


# Used libraries
LDLIBS    += -Wl,--start-group -lc -lgcc -lnosys -Wl,--end-group

###############################################################################
all: elf bin list
elf: $(BINARY).elf
bin: $(BINARY).bin
list: $(BINARY).list

images: $(BINARY).images

$(BINARY).images: $(BINARY).bin $(BINARY).list $(BINARY).map

$(BINARY).bin: $(BINARY).elf
	$(Q)$(OBJCOPY) -Obinary $(BINARY).elf $(BINARY).bin

$(BINARY).list: $(BINARY).elf
	$(Q)$(OBJDUMP) -S $(BINARY).elf > $(BINARY).list

$(BINARY).elf $(BINARY).map: $(OBJS) $(LDSCRIPT)
	$(Q)$(LD) $(LDFLAGS) vector.o $(ARCH_FLAGS) $(OBJS) $(LDLIBS) -o $(BINARY).elf

%.o : %.c
	$(Q)$(CC) -c $(CFLAGS) $(CPPFLAGS) $(ARCH_FLAGS) $< -o $@

%.o : %.s
	$(Q)$(CC) -c $(CFLAGS) $(CPPFLAGS) $(ARCH_FLAGS) $< -o $@

clean:
	$(Q)$(RM) $(BINARY).o $(BINARY).d $(BINARY).elf $(BINARY).bin $(BINARY).list $(BINARY).map


