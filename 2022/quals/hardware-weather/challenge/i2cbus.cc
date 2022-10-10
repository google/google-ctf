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
#include <vector>
#include <cstdio>
#include <cstdlib>
#include "i2cbus.h"

I2CController::I2CController(emu8051 *emu) {
  emu_ = emu;

  for (uint32_t reg: {
      I2CController::I2C_STATUS,
      I2CController::I2C_BUFFER_XRAM_LOW,
      I2CController::I2C_BUFFER_XRAM_HIGH,
      I2CController::I2C_BUFFER_SIZE,
      I2CController::I2C_ADDRESS,
      I2CController::I2C_READ_WRITE
  }) {
    emu_->sfr_register_handler(reg, I2CController::sfr_forwarder, this);
  }
}

void I2CController::register_device_handler(
    uint8_t dev_addr, i2c_dev_handler handler, void *user_data
) {
  i2c_handlers_.at(dev_addr) = handler;
  i2c_handlers_user_data_.at(dev_addr) = user_data;
}

bool I2CController::sfr_forwarder(
    emu8051 */*emu*/,
    emu8051::access_type_t access_type,
    emu8051::address_type_t addr_type, uint8_t addr,
    uint8_t *value, void *user_data
) {
  return ((I2CController*)user_data)->sfr_handler(
      access_type, addr_type, addr, value
  );
}

bool I2CController::sfr_handler(
    emu8051::access_type_t access_type,
    emu8051::address_type_t /*addr_type*/, uint8_t addr,
    uint8_t *value
) {

  if (access_type == emu8051::access_type_t::READ) {
    switch (addr) {
      case I2CController::I2C_STATUS:
        *value = reg_status_;
        return true;

      case I2CController::I2C_BUFFER_XRAM_LOW:
        *value = reg_buffer_xram_low_;
        return true;

      case I2CController::I2C_BUFFER_XRAM_HIGH:
        *value = reg_buffer_xram_high_;
        return true;

      case I2CController::I2C_BUFFER_SIZE:
        *value = reg_buffer_size_;
        return true;

      case I2CController::I2C_ADDRESS:
        *value = reg_i2c_address_;
        return true;

      case I2CController::I2C_READ_WRITE:
        *value = 0;
        return true;

      default:
        // Should never happen.
        fprintf(stderr, "ERROR: I2C controller abort at line %i\n", __LINE__);
        exit(1);
    }
  } else {  // emu8051::access_type_t::WRITE
    switch (addr) {
      case I2CController::I2C_STATUS:
        return true;  // No-op.

      case I2CController::I2C_BUFFER_XRAM_LOW:
        reg_buffer_xram_low_ = *value;
        return true;

      case I2CController::I2C_BUFFER_XRAM_HIGH:
        reg_buffer_xram_high_ = *value;
        return true;

      case I2CController::I2C_BUFFER_SIZE:
        reg_buffer_size_ = *value;
        return true;

      case I2CController::I2C_ADDRESS:
        reg_i2c_address_ = (*value & 0x7f);
        return true;

      case I2CController::I2C_READ_WRITE:
        this->sfr_handle_i2c_execute(*value);
        return true;

      default:
        // Should never happen.
        fprintf(stderr, "ERROR: I2C controller abort at line %i\n", __LINE__);
        exit(1);
    }
  }

  return true;
}

void I2CController::sfr_handle_i2c_execute(uint8_t action) {
  if (i2c_handlers_.at(reg_i2c_address_) == nullptr) {
    reg_status_ = I2CController::I2C_STATUS_NOT_FOUND_ERROR;
    return;
  }

  switch ((action & 1)) {
    case 0:  // Write.
      this->i2c_handle_write_request();
      return;

    case 1:  // Read.
      this->i2c_handle_read_request();
      return;
  }
}

void I2CController::i2c_handle_write_request() {
  // Assumption: Caller checked whether reg_i2c_address_ i2_c handler exists.
  std::vector<uint8_t> buffer;
  buffer.resize(reg_buffer_size_);

  if (reg_buffer_size_) {
    uint16_t xram_addr =
       (((uint16_t)reg_buffer_xram_high_) << 8) |
       reg_buffer_xram_low_;

    // Using direct access since this is technically a DMA controller.
    std::array<uint8_t, 0x10000> &xram = emu_->xram_get_direct();
    for (uint32_t i = 0; i < reg_buffer_size_; i++) {
      buffer.at(i) = xram.at(xram_addr);
      xram_addr++;  // 16-bit overflow here is on purpose and documented.
    }
  }

  auto handler = i2c_handlers_.at(reg_i2c_address_);
  if (handler(
      emu_, emu8051::access_type_t::WRITE, reg_i2c_address_,
      &buffer[0], buffer.size(), i2c_handlers_user_data_.at(reg_i2c_address_)
  )) {
    reg_status_ = I2CController::I2C_STATUS_READY;
  } else {
    reg_status_ = I2CController::I2C_STATUS_DEVICE_ERROR;
  }
}

void I2CController::i2c_handle_read_request() {
  // Assumption: Caller checked whether reg_i2c_address_ i2_c handler exists.
  std::vector<uint8_t> buffer;
  buffer.resize(reg_buffer_size_);

  auto handler = i2c_handlers_.at(reg_i2c_address_);
  if (handler(
      emu_, emu8051::access_type_t::READ, reg_i2c_address_,
      &buffer[0], buffer.size(), i2c_handlers_user_data_.at(reg_i2c_address_)
  )) {
    reg_status_ = I2CController::I2C_STATUS_READY;
  } else {
    reg_status_ = I2CController::I2C_STATUS_DEVICE_ERROR;
    // Copy data to XRAM regardless.
  }

  if (reg_buffer_size_ == 0) {
    return;
  }

  uint16_t xram_addr =
      (((uint16_t)reg_buffer_xram_high_) << 8) |
      reg_buffer_xram_low_;

  // Using direct access since this is technically a DMA controller.
  std::array<uint8_t, 0x10000> &xram = emu_->xram_get_direct();
  for (uint32_t i = 0; i < reg_buffer_size_; i++) {
    xram.at(xram_addr) = buffer.at(i);
    xram_addr++;  // 16-bit overflow here is on purpose and documented.
  }
}
