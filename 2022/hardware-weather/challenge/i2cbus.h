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
// I2C DMA controller module and bus router.
//
// 8051 facing interface:
// - Reading from I2C device:
//   1. Set XRAM buffer address in I2C_BUFFER_XRAM_LOW and I2C_BUFFER_XRAM_HIGH.
//   2. Set how much you want to read in I2C_BUFFER_SIZE.
//   3. Set device 7-bit address in I2C_ADDRESS.
//   4. Write 1 into I2C_READ_WRITE SFR - this will trigger the I2C transaction.
//   5. Check I2C_STATUS for status:
//      0 - Ready / transaction completed.
//      1 - Busy.
//      2 - Error (device not found).
//      3 - Error (device misbehaved).
// - Writing to I2C device:
//   1. to 3. same as above.
//   4. Write 0 into I2C_READ_WRITE SFR - this will trigger the I2C transaction.
//   5. Same as above.
//
// Notes:
// - For all intents and purposes the transactions are always instantaneous,
//   i.e. as soon as the program writes to I2C_READ_WRITE register, the data
//   will appear in the XRAM buffer, and the I2C_STATUS register will be set.
// - Buffer size of 0 will just "ping" the device but not transfer any data.
// - Reading from I2C_READ_WRITE returns 0.
// - Writing to I2C_STATUS is a no-op.
// - Top 7 bits of I2C_READ_WRITE writes are ignored.
// - Top bit of I2C_ADDRESS is hardwired to 0.
// - Setting I2C_BUFFER_XRAM_... and I2C_BUFFER_SIZE in such a way that would
//   overflow XRAM will result in an overlap (i.e. writing/reading iterating
//   address is truncated at 16 bits).
// - If a device misbehaved there still might be some data copied transferred
//   either direction.
//
// Special Function Register declarations for SDCC:
// __sfr __at(0xe1) I2C_STATUS;
// __sfr __at(0xe2) I2C_BUFFER_XRAM_LOW;
// __sfr __at(0xe3) I2C_BUFFER_XRAM_HIGH;
// __sfr __at(0xe4) I2C_BUFFER_SIZE;
// __sfr __at(0xe6) I2C_ADDRESS;  // 7-bit address
// __sfr __at(0xe7) I2C_READ_WRITE;  // 0 is Write, 1 is Read
#pragma once
#include <cstdint>
#include <vector>
#include <array>
#include "emu8051/emu8051.h"

class I2CController {
 public:
  typedef bool (*i2c_dev_handler)(
      emu8051 *emu, emu8051::access_type_t access_type,
      uint8_t dev_addr, void *buffer, uint16_t size,
      void *user_data
  );

  static const uint32_t I2C_STATUS = 0xe1;
  static const uint32_t I2C_BUFFER_XRAM_LOW = 0xe2;
  static const uint32_t I2C_BUFFER_XRAM_HIGH = 0xe3;
  static const uint32_t I2C_BUFFER_SIZE = 0xe4;
  static const uint32_t I2C_ADDRESS = 0xe6;
  static const uint32_t I2C_READ_WRITE = 0xe7;

  static const uint32_t I2C_STATUS_READY = 0;
  static const uint32_t I2C_STATUS_BUSY = 1;  // Technically never set.
  static const uint32_t I2C_STATUS_NOT_FOUND_ERROR = 2;
  static const uint32_t I2C_STATUS_DEVICE_ERROR = 3;

  I2CController(emu8051 *emu);

  void register_device_handler(
      uint8_t dev_addr, i2c_dev_handler handler, void *user_data
  );

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

  void sfr_handle_i2c_execute(uint8_t action);
  void i2c_handle_write_request();
  void i2c_handle_read_request();

  emu8051 *emu_;
  std::array<i2c_dev_handler, 0x80> i2c_handlers_{};
  std::array<void*, 0x80> i2c_handlers_user_data_{};
  uint8_t reg_status_ = 0;
  uint8_t reg_buffer_xram_low_ = 0;
  uint8_t reg_buffer_xram_high_ = 0;
  uint8_t reg_buffer_size_ = 0;
  uint8_t reg_i2c_address_ = 0;
};
