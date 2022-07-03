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
// CTF-55930 EEPROM (relevant excerpt)
//
// This Dual Interface EEPROM allows simultaneous access to data through both
// the I2C and the SPI interface without page locking. EEPROMs capacity depends
// on the exact model:
//
//   CTF-55930A   4096 bits (organized as 8x64x8)
//   CTF-55930B   8192 bits (organized as 16x64x8)
//   CTF-55930C  16384 bits (organized as 32x64x8)
//   CTF-55930D  32768 bits (organized as 64x64x8)
//
// Note: Memory organization is denoted as PAGES x WORDS x BITS_PER_WORD.
//
// In a typical application CTF-55930B serves as firmware storage for CTF-8051
// microcontroller via the SPI(PMEM) bus.
//
// *** Programming the CTF-55930
// Programming this EEPROM is a two-step process. In the first step all bits
// are re-set to 1. In the second step a clear-mask is applied to clear selected
// bits to 0.
// Typical process is as follows:
// 1. Connect all pins apart from Vcc to ground.
// 2. Apply 12V on Vcc pin for at least 100ms.
// 3. [OPTIONAL] Set the 7-bit I2C address - see the Address Setting section for
//    details.
// 4. Disconnect 12V.
// 5. Connect the I2C interface and power on the device.
// 5. Using the I2C interface clear selected bits page by page (64 bytes at a
//    time).
// Note that the SPI interface is immediately active, so it's advised to hold
// the RST pin low on CTF-8051 until programming is complete.
//
// *** I2C interface
// Reading data from a 64-byte page is done in two steps:
// 1. Select the page by writing the page index to EEPROM's I2C address.
// 2. Receive up to 64 bytes by reading from the EEPROM's I2C address.
//
// Programming the EEPROM is done by writing the following packet to the
// EEPROM's I2C address:
//
//     <PageIndex> <4ByteWriteKey> <ClearMask> ... <ClearMask>
//
// The PageIndex selects a 64-byte page to operate on.
// The WriteKey is a 4 byte unlock key meant to prevent accidental overwrites.
// Its value is constant: A5 5A A5 5A
// Each ClearMask byte is applied to the consecutive bytes of the page, starting
// from byte at index 0. All bits set to 1 in the ClearMask are cleared (set to
// 0) for the given byte in the given page on the EEPROM:
//
//     byte[i] <-- byte[i] AND (NOT clear_mask_byte)
//
// Note: The only way to bring a bit back to 1 is to follow the 12V full memory
// reset described in the "Programming the CTF-55930" section.
#pragma once
#include <cstdint>
#include <vector>
#include "emu8051/emu8051.h"
#include "i2cbus.h"

class DualEEPROMDevice {
 public:
  DualEEPROMDevice(emu8051 *emu, I2CController *i2cbus, uint8_t i2c_addr);

  void set_capacity(uint32_t new_capacity);  // In bytes.
  void store_at(uint16_t addr, uint8_t *data, uint16_t size);

 private:
  static void pmem_forwarder(
      emu8051 *emu,
      emu8051::access_type_t access_type,
      uint16_t addr, uint8_t *value,
      void *user_data
  );

  void pmem_controller(
      emu8051::access_type_t access_type,
      uint16_t addr, uint8_t *value
  );

  static bool i2c_forwarder(
      emu8051 *emu, emu8051::access_type_t access_type,
      uint8_t dev_addr, void *buffer, uint16_t size,
      void *user_data);

  bool i2c_handler(
      emu8051::access_type_t access_type,
      uint8_t dev_addr, void *buffer, uint16_t size
  );

  emu8051 *emu_;
  uint8_t i2c_addr_{};  // 7-bit I2C address.
  uint8_t reg_i2c_page_{};
  std::vector<uint8_t> mem_;
};
