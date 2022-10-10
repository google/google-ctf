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
// A set of fake I2C connected devices.
//
// 119: Humidity sensor.
//      Returns 1 byte value from 0 to 100.
//
// 110: Light sensor A.
// 111: Light sensor B.
//      Returns 1 byte value from 0 to 200.
//
// 108: Atmospheric pressure sensor.
//      Returns 1 big-endian encoded 2-byte number
//
// 101: Set of 4 thermometers.
//      Returns 4 numbers 1-byte each - temperature in Celsius.
//
// Notes:
// - Writing to any of these devices is a no-op.
#pragma once
#include "emu8051/emu8051.h"
#include "i2cbus.h"

class FakeI2CDevices {
 public:
  static const uint8_t I2C_ADDR_HUMIDITY_SENSOR = 119;
  static const uint8_t I2C_ADDR_LIGHT_SENSOR_A = 110;
  static const uint8_t I2C_ADDR_LIGHT_SENSOR_B = 111;
  static const uint8_t I2C_ADDR_BAROMETER = 108;
  static const uint8_t I2C_ADDR_THERMOMETERS = 101;

  FakeI2CDevices(emu8051 *emu, I2CController *i2cbus);

 private:
  static bool i2c_forwarder(
      emu8051 *emu, emu8051::access_type_t access_type,
      uint8_t dev_addr, void *buffer, uint16_t size,
      void *user_data);

  bool i2c_handler(
      emu8051::access_type_t access_type,
      uint8_t dev_addr, void *buffer, uint16_t size
  );

  emu8051 *emu_;
};
