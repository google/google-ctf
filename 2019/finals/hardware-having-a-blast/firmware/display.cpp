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
#include "display.h"

#include "config.h"

namespace Display {

void clear(bool auto_strobe) {
  for (int i = 0; i < 6; i++) {
    send_7seg(0);
  }
  if (auto_strobe) {
    strobe();
  }
}

void send_7seg(uint8_t value) {
  for (int b = 0; b < 8; b++) {
    send_single((value & (1 << b)) != 0);
  }
  delayMicroseconds(MIN_DELAY_OPTOCOUPLER_US * 1);
}

void send_single(bool b) {
  digitalWrite(DATA_PIN, b ? HIGH : LOW);
  clock();
}

void clock() {
  digitalWrite(CLK_PIN, LOW);
  delayMicroseconds(MIN_DELAY_OPTOCOUPLER_US);
  digitalWrite(CLK_PIN, HIGH);
  delayMicroseconds(MIN_DELAY_OPTOCOUPLER_US);
}

void strobe() {
  digitalWrite(STROBE_PIN, LOW);
  delayMicroseconds(MIN_DELAY_OPTOCOUPLER_US);
  digitalWrite(STROBE_PIN, HIGH);
  delayMicroseconds(MIN_DELAY_OPTOCOUPLER_US);
}

void init() {
  digitalWrite(CLK_PIN, HIGH);
  digitalWrite(STROBE_PIN, HIGH);
  digitalWrite(DATA_PIN, HIGH);
}

}  // namespace Display
