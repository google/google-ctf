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
#include <cstdlib>
#include "progeeprom.h"

DualEEPROMDevice::DualEEPROMDevice(
    emu8051 *emu, I2CController *i2cbus, uint8_t i2c_addr
) {
  emu_ = emu;
  emu_->pmem_register_controller(DualEEPROMDevice::pmem_forwarder, this);

  i2c_addr_ = i2c_addr;
  i2cbus->register_device_handler(
      i2c_addr, DualEEPROMDevice::i2c_forwarder, this
  );
}

void DualEEPROMDevice::set_capacity(uint32_t new_capacity) {
  switch (new_capacity) {
    case 4096 / 8:
    case 8192 / 8:
    case 16384 / 8:
    case 32768 / 8:
      mem_.resize(new_capacity);
      return;
  }

  fprintf(stderr, "ERROR: ProgEEPROM device invalid capacity requested\n");
  exit(1);
}

void DualEEPROMDevice::store_at(uint16_t addr, uint8_t *data, uint16_t size) {
  for (uint32_t i = 0; i < size; i++) {
    mem_.at(i + addr) = data[i];
  }
}

void DualEEPROMDevice::pmem_forwarder(
    emu8051 */*emu*/,
    emu8051::access_type_t access_type,
    uint16_t addr, uint8_t *value,
    void *user_data
) {
  ((DualEEPROMDevice*)user_data)->pmem_controller(access_type, addr, value);
}

void DualEEPROMDevice::pmem_controller(
    emu8051::access_type_t access_type,
    uint16_t addr, uint8_t *value
) {
  if (access_type == emu8051::access_type_t::WRITE) {
    return;
  }

  if (mem_.size() == 0) {
    fprintf(stderr, "ERROR: ProgEEPROM device capacity not set\n");
    exit(1);
  }

  // Note: Capacity is a power of two (see set_capacity).
  const uint16_t masked_addr = addr & (mem_.size() - 1);
  *value = mem_.at(masked_addr);
}

bool DualEEPROMDevice::i2c_forwarder(
      emu8051 */*emu*/, emu8051::access_type_t access_type,
      uint8_t dev_addr, void *buffer, uint16_t size,
      void *user_data) {
  return ((DualEEPROMDevice*)user_data)->i2c_handler(
      access_type, dev_addr, buffer, size
  );
}

bool DualEEPROMDevice::i2c_handler(
      emu8051::access_type_t access_type,
      uint8_t /*dev_addr*/, void *buffer, uint16_t size
) {
  uint8_t *byte_buffer = (uint8_t*)buffer;
  const uint8_t page_max = (uint8_t)(mem_.size() / 64);

  if (access_type == emu8051::access_type_t::WRITE) {
    if (size >= 1) {
      reg_i2c_page_ = byte_buffer[0] & (page_max - 1);  // Grab the page index.
    }

    if (size <= 5) {
      // Nothing to do if there is no data to write.
      return true;
    }

    if (byte_buffer[1] != 0xA5 ||
        byte_buffer[2] != 0x5A ||
        byte_buffer[3] != 0xA5 ||
        byte_buffer[4] != 0x5A) {
      return true;
    }

    int clear_mask_count = std::min(size - 5, 64);
    uint8_t *clear_masks = byte_buffer + 5;
    for (int i = 0; i < clear_mask_count; i++) {
      mem_.at(reg_i2c_page_ * 64 + i) &= ~clear_masks[i];
    }

    return true;
  }

  int req_byte_count = std::min(+size, 64);
  for (int i = 0; i < req_byte_count; i++) {
    byte_buffer[i] = mem_.at(reg_i2c_page_ * 64 + i);
  }

  return true;
}
