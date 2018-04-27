/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



#pragma once
#include <stdint.h>

namespace Input {

// We have a 12 pin connector to the button panel
constexpr unsigned long max_num_buttons = 12;

// Initialize the IO pins for the buttons.
void init();

// idx elem [0..4]
bool is_button_pressed(uint8_t idx);

// For now..
bool is_spin_pressed();
bool is_bet_pressed();
} // namespace Input
