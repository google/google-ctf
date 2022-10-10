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
#include <algorithm>
#include <initializer_list>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include "fakei2cdev.h"

FakeI2CDevices::FakeI2CDevices(emu8051 *emu, I2CController *i2cbus) {
  emu_ = emu;

  for (uint8_t i2c_addr: {
    FakeI2CDevices::I2C_ADDR_HUMIDITY_SENSOR,
    FakeI2CDevices::I2C_ADDR_LIGHT_SENSOR_A,
    FakeI2CDevices::I2C_ADDR_LIGHT_SENSOR_B,
    FakeI2CDevices::I2C_ADDR_BAROMETER,
    FakeI2CDevices::I2C_ADDR_THERMOMETERS
  }) {
    i2cbus->register_device_handler(
        i2c_addr, FakeI2CDevices::i2c_forwarder, this
    );
  }
}

bool FakeI2CDevices::i2c_forwarder(
      emu8051 */*emu*/, emu8051::access_type_t access_type,
      uint8_t dev_addr, void *buffer, uint16_t size,
      void *user_data) {
  return ((FakeI2CDevices*)user_data)->i2c_handler(
      access_type, dev_addr, buffer, size
  );
}

bool FakeI2CDevices::i2c_handler(
      emu8051::access_type_t access_type,
      uint8_t dev_addr, void *buffer, uint16_t size
) {
  if (access_type == emu8051::access_type_t::WRITE) {
    return true;  // No-op.
  }

  switch (dev_addr) {
    case FakeI2CDevices::I2C_ADDR_HUMIDITY_SENSOR:
      memcpy(buffer, "\x25", std::min(uint16_t(1), size));  // 37%
      return true;

    case FakeI2CDevices::I2C_ADDR_LIGHT_SENSOR_A:
      memcpy(buffer, "\x4e", std::min(uint16_t(1), size));
      return true;

    case FakeI2CDevices::I2C_ADDR_LIGHT_SENSOR_B:
    memcpy(buffer, "\x51", std::min(uint16_t(1), size));
      return true;

    case FakeI2CDevices::I2C_ADDR_BAROMETER:
      memcpy(buffer, "\x03\xf9", std::min(uint16_t(2), size));  // 1017 hPa.
      return true;

    case FakeI2CDevices::I2C_ADDR_THERMOMETERS:
      // 22C, 22C, 21C and 35C.
      memcpy(buffer, "\x16\x16\x15\x23", std::min(uint16_t(4), size));
      return true;

    default:
      // Should never happen.
      fprintf(stderr, "ERROR: Sensor I2C device abort at line %i\n", __LINE__);
      exit(1);
  }
}
