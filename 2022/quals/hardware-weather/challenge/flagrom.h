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
//
//
// An SFR-accessible ROM containing the flag.
//
// A very simple factory-programmed ROM device with an SFR-mapped interface.
// The ROM has capacity to store up to 2048 bits (256x8).
//
// To read the data from the ROM simply set the FLAGROM_ADDR register to the
// byte index and read the byte value from the FLAGROM_DATA register.
//
// Reading from the FLAGROM_ADDR register returns the currently set address.
// Writing to FLAGROM_DATA register is a no-op.
//
// Special Function Register declarations for SDCC:
// __sfr __at(0xee) FLAGROM_ADDR;
// __sfr __at(0xef) FLAGROM_DATA;
#pragma once
#include <cstdint>
#include "emu8051/emu8051.h"

class FlagROMDevice {
 public:
  static const uint32_t FLAGROM_ADDR = 0xee;
  static const uint32_t FLAGROM_DATA = 0xef;

  FlagROMDevice(emu8051 *emu, const char *flag_file);

 private:
  static bool sfr_forwarder(
      emu8051 *emu,
      emu8051::access_type_t access_type,
      emu8051::address_type_t addr_type, uint8_t addr,
      uint8_t *value, void *user_data
  );

  bool sfr_handler(
      emu8051::access_type_t access_type,
      emu8051::address_type_t addr_type, uint8_t addr,
      uint8_t *value
  );

  emu8051 *emu_;
  uint8_t address_{};
  uint8_t flag_buffer_[256]{};
};


