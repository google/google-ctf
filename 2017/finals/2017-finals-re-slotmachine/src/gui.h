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

#include "ILI9225.h"
#include "item.h"

// Graphic routines
namespace GUI {
constexpr uint16_t foreground_color = COLOR_WHITE;
constexpr uint16_t background_color = RGB888_RGB565(0x470a06);
constexpr uint16_t gui_font_bg_color = RGB888_RGB565(0xa30100);

void set_field(uint8_t idx, uint8_t idy, Item::type_t state);
void set_points(uint16_t points);
void set_bet(uint8_t bet);

// Animations
void spin_col(uint8_t idx_x, const Item::type_t state[3]);

// Do some fancy animations when hitting the jackpot
void jackpot(const char *flag);

// Very secret!
void secret_developer_menu();

// One model has limited screen visibility, use a y offset to compensate
constexpr uint16_t model_y_offset =
#if MODEL == 3 || MODEL == 4
    10
#else
    0
#endif
    ;

} // namespace GUI
