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
#include "bomb.h"

#include "config.h"
#include "display.h"

void Bomb::tick() {
  // Wait until the light sensor detected the start.
  if (is_input_set(CircuitInput::LightSensor) && !skip_lightsensor_) {
    Display::clear(true);
    return;
  }

  // Light sensor was triggered once.
  skip_lightsensor_ = true;

  if (time_remaining_ == 0) {
    return;
  }

  if (defused_) {
    // Blink remaining time on defusal.
    Display::clear(true);
    delay(400);
    send_remaining_time(time_remaining_);
    delay(400);
    return;
  }

  send_remaining_time(time_remaining_);

  wait_for_edge(true);
  check_password_if_requested();

  uint32_t time_delta = kTimeDeltaPerRound;
  if (tamper_detected_a || tamper_detected_b) {
    time_delta *= kTamperDetectionMultiplicator;
    if (!tamper_reported) {
      mt_send_mqtt_event("tamper_start");
      tamper_reported = true;
    }
  } else if(tamper_reported) {
    mt_send_mqtt_event("tamper_end");
    tamper_reported = false;
  }

  if (password_state_ == PasswordCheckStatus::Incorrect) {
    time_delta += 60 * 1000;
  }

  if (!is_input_set(CircuitInput::Wire2)) {
    time_delta = time_remaining_;
  }

  if (password_state_ == PasswordCheckStatus::Correct &&
      !is_input_set(CircuitInput::Wire1) &&
      is_input_set(CircuitInput::Wire2)) {
    if (on_defuse_) {
      on_defuse_();
    }
    defused_ = true;
    return;
  }

  bool should_beep = time_remaining_ / 1000 > (time_remaining_ - time_delta) / 1000;

  if (time_remaining_ < time_delta) {
    time_remaining_ = 0;
  } else {
    time_remaining_ -= time_delta;
  }

  send_remaining_time(time_remaining_);
  if (should_beep) {
    portENTER_CRITICAL(&mux);
    disable_spkr_in = 50;
    if (tamper_detected_a || tamper_detected_b) {
      disable_spkr_in = 100;
    }
    timerRestart(spkr_timer);
    timerAlarmEnable(spkr_timer);
    portEXIT_CRITICAL(&mux);
  }

  wait_for_edge(false);

  if (time_remaining_ == 0) {
    if (on_explode_) {
      on_explode_();
    }
  }
}

// 6 segments, MM:SS:ms
void Bomb::send_remaining_time(uint32_t time_ms) {
  int minutes = (time_ms / 1000 / 60) % 60;
  int seconds = (time_ms / 1000) % 60;
  int ms = time_ms % 1000;

  uint8_t send_to_display[6] = {static_cast<uint8_t>(minutes / 10),
                                static_cast<uint8_t>(minutes % 10),
                                static_cast<uint8_t>(seconds / 10),
                                static_cast<uint8_t>(seconds % 10),
                                static_cast<uint8_t>(ms / 100),
                                static_cast<uint8_t>((ms % 100) / 10)};

  uint8_t mask = 0;
  if (password_state_ == PasswordCheckStatus::Correct) {
    mask |= 1;  // Show the dot if the password was correct.
  }

  for (int i = 0; i < 6; i++) {
    Display::send_7seg(Display::NUM_TO_SEG[send_to_display[5 - i]] | mask);
  }

  Display::strobe();
}

extern bool send_event;
extern String event_to_send;

void Bomb::check_password_if_requested() {
  PasswordCheckStatus new_state = password_state_;

  // Lock in good state if good password was entered.
  if (password_state_ == PasswordCheckStatus::Correct) {
    return;
  }

  bool should_check_password = is_input_set(CircuitInput::DoPasswordCheck);

  switch (password_state_) {
    case PasswordCheckStatus::Correct:
      // After the correct password was entered, we disable the button.
      return;
    case PasswordCheckStatus::Incorrect:
      new_state = PasswordCheckStatus::Hold;
    break;
    case PasswordCheckStatus::None:
      if (should_check_password) {
        if (is_input_set(CircuitInput::PasswordResult)) {
          new_state = PasswordCheckStatus::Correct;
          on_correct_password();
        } else {
          new_state = PasswordCheckStatus::Incorrect;
          on_incorrect_password();
        }
      }
    break;
    case PasswordCheckStatus::Hold:
      if (!should_check_password) {
        new_state = PasswordCheckStatus::None;
      }
    break;
  }

  password_state_ = new_state;
}

void Bomb::wait_for_edge(bool falling) {
  uint32_t pulse_delay = 0;
  while (is_input_set(CircuitInput::ClockPulse) == falling) {
    pulse_delay++;
    if (pulse_delay > kClockTimeout) {
      break;
    }
  }
  if (falling) {
    tamper_detected_a = pulse_delay > kClockTimeout;
  } else {
    tamper_detected_b = pulse_delay > kClockTimeout;
  }
}
