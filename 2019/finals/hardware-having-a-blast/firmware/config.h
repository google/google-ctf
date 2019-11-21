/******************************************************************************
 * Copyright 2018 Google
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *****************************************************************************/
#pragma once

#include "Arduino.h"

#include <cstdint>

// Pin configuration
// MCU output pins:
const int CLK_PIN =                0;
const int STROBE_PIN =             2;
const int DATA_PIN =               4;

// MCU input pins:
const int LIGHT_SENSOR_PIN =       5;
const int WIRE1_PIN =             15;
const int PASSWORD_PIN =          16;
const int CLOCK_IN_PIN =          17;
const int DO_PASSWORD_CHECK_PIN = 18;
const int WIRE2_PIN =             19;

// Small speaker hooked directly to the MCU.
const int SPEAKER_PIN           = 27;

// 11 is the minimum stable value, let's pick one more to be on the safe side.
const int MIN_DELAY_OPTOCOUPLER_US = 12;

enum class CircuitInput {
  LightSensor,
  Wire1,
  Wire2,
  ClockPulse,
  PasswordResult,
  DoPasswordCheck,
};

inline bool is_input_set(CircuitInput input) {
  switch (input) {
    case CircuitInput::LightSensor:
      return !digitalRead(LIGHT_SENSOR_PIN);
    case CircuitInput::Wire1:
      return !digitalRead(WIRE1_PIN);
    case CircuitInput::Wire2:
      return !digitalRead(WIRE2_PIN);
    case CircuitInput::ClockPulse:
      return !digitalRead(CLOCK_IN_PIN);
    case CircuitInput::PasswordResult:
      return !digitalRead(PASSWORD_PIN);
    case CircuitInput::DoPasswordCheck:
      return !digitalRead(DO_PASSWORD_CHECK_PIN);
    default:
      /* unreachable */
      return false;
  }
}

extern bool send_event;
extern String event_to_send;
extern hw_timer_t *spkr_timer;
extern int disable_spkr_in;

extern portMUX_TYPE mux;

inline void mt_send_mqtt_event(const String &event) {
  event_to_send = event;
  send_event = true;
}
