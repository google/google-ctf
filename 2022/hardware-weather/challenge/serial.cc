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

#include "serial.h"

SerialDevice::SerialDevice(emu8051 *emu) {
  emu_ = emu;

  for (uint32_t reg: {
      SerialDevice::SERIAL_OUT_DATA,
      SerialDevice::SERIAL_OUT_READY,
      SerialDevice::SERIAL_IN_DATA,
      SerialDevice::SERIAL_IN_READY
  }) {
    emu_->sfr_register_handler(reg, SerialDevice::sfr_forwarder, this);
  }
}

bool SerialDevice::sfr_forwarder(
      emu8051 */*emu*/,
      emu8051::access_type_t access_type,
      emu8051::address_type_t addr_type, uint8_t addr,
      uint8_t *value, void *user_data) {
  return ((SerialDevice*)user_data)->sfr_handler(
      access_type, addr_type, addr, value
  );
}

bool SerialDevice::sfr_handler(
    emu8051::access_type_t access_type,
    emu8051::address_type_t /*addr_type*/, uint8_t addr,
    uint8_t *value
  ) {

  if (access_type == emu8051::access_type_t::READ) {
    switch (addr) {
      case SerialDevice::SERIAL_OUT_DATA:
        *value = 0;  // Always return 0.
        return true;

      case SerialDevice::SERIAL_OUT_READY:
        *value = 1;  // Always return 1.
        return true;

      case SerialDevice::SERIAL_IN_DATA:
        return this->sfr_handle_input_read_data(value);

      case SerialDevice::SERIAL_IN_READY:
        return this->sfr_handle_input_read_ready(value);

      default:
        // Should never happen.
        fprintf(stderr, "ERROR: Serial device abort at line %i\n", __LINE__);
        exit(1);
    }
  } else {  // emu8051::access_type_t::WRITE
    switch (addr) {
      case SerialDevice::SERIAL_OUT_DATA:
        return this->sfr_handle_output_write_data(*value);

      case SerialDevice::SERIAL_IN_READY:
      case SerialDevice::SERIAL_OUT_READY:
      case SerialDevice::SERIAL_IN_DATA:
        return true;  // No-op.

      default:
        // Should never happen.
        fprintf(stderr, "ERROR: Serial device abort at line %i\n", __LINE__);
        exit(1);
    }
  }

  // Should never reach this place.
  fprintf(stderr, "ERROR: Serial device abort at line %i\n", __LINE__);
  exit(1);
}

bool SerialDevice::sfr_handle_input_read_data(uint8_t *value) {
  this->update_stdin_status();
  if (!input_ready_) {
    *value = 0;
    return true;
  }

  *value = input_byte_;
  input_ready_ = false;
  return true;
}

bool SerialDevice::sfr_handle_input_read_ready(uint8_t *value) {
  this->update_stdin_status();
  *value = (uint8_t)input_ready_;
  return true;
}

bool SerialDevice::sfr_handle_output_write_data(uint8_t value) {
  putchar((int)value);
  return true;
}

void SerialDevice::update_stdin_status() {
  if (input_ready_) {
    return;  // Data is alreadt waiting to be picked up.
  }

  pollfd stdin_fd = { 0, POLLIN, 0 };
  int ret = poll(&stdin_fd, /*nfds=*/1, /*timeout=*/0);

  // There is no data in case:
  // - poll failed (negative number),
  // - poll didn't select stdin (zero),
  // - poll did select stdin, but there is no data there (just another event).
  if (ret <= 0 || (stdin_fd.revents & POLLIN) == 0) {
    return;
  }

  // Attempt to read data.
  int ch = getchar();
  if (ch == EOF) {
    // No data is available (might happen if socket/pipe was closed in this
    // direction).
    return;
  }

  input_byte_ = (uint8_t)ch;
  input_ready_ = true;
}
