// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <poll.h>
#include "emu8051/emu8051.h"

#include "flagrom.h"

FlagROMDevice::FlagROMDevice(emu8051 *emu, const char *flag_file) {
  emu_ = emu;

  for (uint32_t reg: {
      FlagROMDevice::FLAGROM_ADDR,
      FlagROMDevice::FLAGROM_DATA
  }) {
    emu_->sfr_register_handler(reg, FlagROMDevice::sfr_forwarder, this);
  }

  FILE *f = fopen(flag_file, "rb");
  if (f == nullptr) {
    fprintf(stderr, "ERROR: FlagROM can't access file with flag!\n");
    exit(1);
  }

  fread(flag_buffer_, 256, 1, f);
  fclose(f);
}

bool FlagROMDevice::sfr_forwarder(
      emu8051 */*emu*/,
      emu8051::access_type_t access_type,
      emu8051::address_type_t addr_type, uint8_t addr,
      uint8_t *value, void *user_data) {
  return ((FlagROMDevice*)user_data)->sfr_handler(
      access_type, addr_type, addr, value
  );
}

bool FlagROMDevice::sfr_handler(
    emu8051::access_type_t access_type,
    emu8051::address_type_t /*addr_type*/, uint8_t addr,
    uint8_t *value
  ) {

  if (access_type == emu8051::access_type_t::READ) {
    switch (addr) {
      case FlagROMDevice::FLAGROM_ADDR:
        *value = address_;
        return true;

      case FlagROMDevice::FLAGROM_DATA:
        *value = flag_buffer_[address_];
        return true;

      default:
        // Should never happen.
        fprintf(stderr, "ERROR: FlagROM device abort at line %i\n", __LINE__);
        exit(1);
    }
  } else {  // emu8051::access_type_t::WRITE
    switch (addr) {
      case FlagROMDevice::FLAGROM_ADDR:
        address_ = *value;
        return true;

      case FlagROMDevice::FLAGROM_DATA:
        return true;  // No-op.

      default:
        // Should never happen.
        fprintf(stderr, "ERROR: FlagROM device abort at line %i\n", __LINE__);
        exit(1);
    }
  }

  // Should never reach this place.
  fprintf(stderr, "ERROR: FlagROM device abort at line %i\n", __LINE__);
  exit(1);
}
