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
// A simplified serial communication device.
//
// This device makes available two sets of ports for the 8051 to use to
// communicate over a pseudo-serial interface. Each set consists of a DATA SFR
// (Special Function Register) and a READY SFR.
//
// Note: "output" denotes outgoing data from the 8051, while "input" denotes
// data sent to the 8051.
//
// In case of the output SFR set (DATA @ 0xF2, READY @ 0xF3), the READY is set
// to 1 in case serial module is able to receive another byte of data to
// transmit. In practice READY will be set to 1 immediately after a byte is
// written to DATA since this pseudo-serial device transmits data
// instantaneously.
//
// In case of the input SFR set (DATA @ 0xFA, READY @ 0xFB), the READY is set
// to 1 in case a byte is available to be received by the 8051. A read from the
// DATA SFR removes the read byte from the serial buffer and resets the READY
// SFR to 0 (if there is no more data at the moment) or 1 (if more data is
// immediately available).
//
// Writing to input DATA SFR is a no-op.
// Writing to input READY SFR is a no-op.
// Writing to output READY SFR is a no-op.
// Reading from the output DATA SFR port returns 0.
// Reading from the input DATA SFR if READY SFR is 0 returns 0.
//
// Special Function Register declarations for SDCC:
// __sfr __at(0xf2) SERIAL_OUT_DATA;
// __sfr __at(0xf3) SERIAL_OUT_READY;
// __sfr __at(0xfa) SERIAL_IN_DATA;
// __sfr __at(0xfb) SERIAL_IN_READY;
#pragma once
#include <cstdint>
#include "emu8051/emu8051.h"

class SerialDevice {
 public:
  static const uint32_t SERIAL_OUT_DATA = 0xf2;
  static const uint32_t SERIAL_OUT_READY = 0xf3;
  static const uint32_t SERIAL_IN_DATA = 0xfa;
  static const uint32_t SERIAL_IN_READY = 0xfb;

  SerialDevice(emu8051 *emu);

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

  bool sfr_handle_input_read_data(uint8_t *value);
  bool sfr_handle_input_read_ready(uint8_t *value);
  bool sfr_handle_output_write_data(uint8_t value);
  void update_stdin_status();

  emu8051 *emu_;
  uint8_t input_byte_;
  bool input_ready_ = false;

};


