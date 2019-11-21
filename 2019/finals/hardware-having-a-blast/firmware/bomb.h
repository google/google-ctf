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

#include "config.h"
#include "display.h"

class Bomb {
 public:
  using Callback = void (*)();

  Bomb() {}

  void tick();

  void set_on_explode(Callback c) { on_explode_ = c; }
  void set_on_defuse(Callback c) { on_defuse_ = c; }

  void defuse() {
    password_state_ = PasswordCheckStatus::Correct;
    defused_ = true;
    if (on_defuse_) {
      on_defuse_();
    }
  }

  uint32_t time_remaining() { return time_remaining_; }
  void skip_lightsensor() { skip_lightsensor_ = true; }

 private:
  enum class PasswordCheckStatus {
    None,
    Incorrect,
    Correct,
    Hold,
  };

  void check_password_if_requested();
  void wait_for_edge(bool falling);

  // 6 segments. MM:SS:ms
  void send_remaining_time(uint32_t time_ms);

  void on_incorrect_password() {
    mt_send_mqtt_event("incorrect_password");
    Serial.println("Password incorrect");
  }

  void on_correct_password() {
    mt_send_mqtt_event("correct_password");
    Serial.println("Password correct");

    for (int i = 0; i < 3; i++) {
      Display::clear();
      Display::strobe();
      delay(500);
      Display::send_7seg(Display::S);
      Display::send_7seg(Display::E);
      Display::send_7seg(Display::Y);
      Display::strobe();
      delay(500);
    }

    Display::clear();
  }

  Callback on_explode_ = nullptr;
  Callback on_defuse_ = nullptr;

  // Start with 20 minutes on the clock.
  uint32_t time_remaining_ = (20 * 60 + 00) * 1000 + 0;
  bool skip_lightsensor_ = false;
  bool defused_ = false;

  // Password protection check.
  PasswordCheckStatus password_state_ = PasswordCheckStatus::None;

  // Clock too slow? (timeout waiting for rising / falling edge).
  bool tamper_detected_a = false;
  bool tamper_detected_b = false;
  bool tamper_reported = false;

  // Time delta in ms to substract each cycle.
  // Run slightly faster than 1s per second to avoid overrunning the timeslot at 220nF.
  // 555 timer will run at 48.1Hz by default (which will be 20.79ms).
  //  -> substracting 22ms per cycle makes one 'bomb second' <=> 0.945s (off by 5%).
  // After swapping the capacitor:
  //  f = 21.864 => 0.481s per 'bomb second' -> 2.08 times the actual time.
  static constexpr uint32_t kTimeDeltaPerRound = 22;

  // Timeout to detect that the clock ticks too slow. I absolutely have the math somewhere
  // for this, trust me!11.
  static constexpr uint32_t kClockTimeout = 240 * 1000 * 1000 / (80 * 20) / 2;

  static constexpr uint32_t kTamperDetectionMultiplicator = 20;
};
