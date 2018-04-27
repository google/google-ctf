// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.



#include "gui.h"
#include "ILI9225.h"
#include "assets.h"
#include "input.h"
#include "rng.h"
#include <util/delay.h>

constexpr uint8_t length(const char *str) {
    return *str ? length(str + 1) + 1 : 0;
}

// Field offsets
constexpr uint16_t field_width = 50;
constexpr uint16_t field_height = 40;
constexpr uint16_t field_padding_horizontal = 12;
constexpr uint16_t field_padding_vertical = 2;
constexpr uint16_t field_offset_x = 23;
constexpr uint16_t field_offset_y = 34 + GUI::model_y_offset;

// Points / Bet display offsets
constexpr char str_points[] PROGMEM = "Points: ";
constexpr uint16_t points_str_x = 95;
constexpr uint16_t points_x =
    points_str_x + length(str_points) * (char_width + 1);
constexpr uint16_t points_y = 5 + GUI::model_y_offset;

constexpr char str_bet[] PROGMEM = "Your bet: ";
constexpr uint16_t bet_str_x = 4;
constexpr uint16_t bet_x = bet_str_x + length(str_bet) * (char_width + 1);
constexpr uint16_t bet_y = 5 + GUI::model_y_offset;

// Return the start coordinate of the field @ idx_x
constexpr uint16_t field_x_begin(uint8_t idx_x) {
    return field_offset_x + idx_x * (field_width + field_padding_horizontal);
}

constexpr uint16_t field_x_end(uint8_t idx_x) {
    return field_x_begin(idx_x) + field_width;
}

// Similar for the y coordinates
constexpr uint16_t field_y_begin(uint8_t idx_y) {
    return field_offset_y + idx_y * (field_height + field_padding_vertical);
}

constexpr uint16_t field_y_end(uint8_t idx_y) {
    return field_y_begin(idx_y) + field_height;
}

namespace GUI {

void set_field(uint8_t idx_x, uint8_t idx_y, Item::type_t state) {
    if (state > 4) {
        // Shouldn't happen...
        state = Item::None;
    }

    if (state == Item::None) {
        Display::fill_box(field_x_begin(idx_x), field_y_begin(idx_y),
                          field_x_end(idx_x), field_y_end(idx_y),
                          background_color);
    } else {
        Assets::type_t to_draw;
        switch (state) {
        case Item::Single:
            to_draw = Assets::BAR;
            break;
        case Item::Double:
            to_draw = Assets::LEMON;
            break;
        case Item::Triple:
            to_draw = Assets::SEVEN;
            break;
        default: // Unreachable
            return;
        }

        Assets::draw_asset(to_draw, field_x_begin(idx_x), field_y_begin(idx_y),
                           field_width, field_height);
    }
}

void set_points(uint16_t points) {
    Display::draw_text_pgm(str_points, points_str_x, points_y, foreground_color,
                           gui_font_bg_color);
    Display::draw_numbers(points, 5, points_x, points_y, foreground_color,
                          gui_font_bg_color);
}

constexpr uint16_t nr_steps = 5;

constexpr uint16_t calculate_col_spin(uint16_t org_y, uint16_t step) {
    constexpr uint16_t stepsize =
        (field_y_end(2) - field_y_begin(0)) / nr_steps;
    uint16_t r = org_y + step * stepsize;
    if (r > field_y_end(2)) {
        return r - field_y_end(2) + field_y_begin(0) + model_y_offset;
    }
    return r + model_y_offset;
}

void spin_col(uint8_t idx_x, const Item::type_t state[3]) {
    constexpr uint16_t spin_bar_color = COLOR_BLACK;
    // Do some spinning animation for the col(idx_x), resulting state in state
    uint8_t n_rounds = 5;

    // Clear the column
    Display::fill_box(field_x_begin(idx_x), field_y_begin(0),
                      field_x_end(idx_x), field_y_end(2), background_color);

    for (uint8_t i = 0; i < n_rounds; i++) {
        for (uint8_t step = 0; step < nr_steps; step++) {
            for (uint8_t n = 0; n < 2; n++) {
                // n = 0 -> draw lines, 1 -> remove lines
                for (uint8_t idx_y = 0; idx_y < 3; idx_y++) {
                    Display::draw_line(
                        field_x_begin(idx_x) + 1,
                        calculate_col_spin(field_y_begin(idx_y), step),
                        field_x_end(idx_x),
                        calculate_col_spin(field_y_begin(idx_y), step),
                        n == 0 ? spin_bar_color : background_color);
                }
                if (n == 0) {
                    _delay_ms(20);
                }
            }
        }
    }

    Display::draw_line(field_x_begin(idx_x) + 1, 75 + model_y_offset,
                       field_x_end(idx_x), 75 + model_y_offset, spin_bar_color);

    Display::draw_line(field_x_begin(idx_x) + 1, 117 + model_y_offset,
                       field_x_end(idx_x), 117 + model_y_offset,
                       spin_bar_color);

    for (uint8_t y = 0; y < 3; y++) {
        set_field(idx_x, y, state[y]);
    }
}

void set_bet(uint8_t bet) {
    // Draw POINTS: prior to the actual points
    Display::draw_text_pgm(str_bet, bet_str_x, bet_y, foreground_color,
                           gui_font_bg_color);
    Display::draw_number(bet, bet_x, bet_y, foreground_color,
                         gui_font_bg_color);
}

const uint16_t colors[] = {COLOR_RED,  COLOR_ORANGE, COLOR_YELLOW, COLOR_GREEN,
                           COLOR_CYAN, COLOR_BLUE,   COLOR_VIOLET};

void jackpot(const char *flag) {
    constexpr int8_t sin_offsets[] = {
        0, 1,  3,  5,  6,  7,  8,  9,  9,  9,  9,  9,  8,  7,  5,  4,  2, 0,
        0, -2, -4, -5, -7, -8, -9, -9, -9, -9, -9, -8, -7, -6, -5, -3, -1};
    Display::clear(COLOR_BLACK);
    static uint8_t color = 0;

    Display::draw_text("Congratulations!", 65, model_y_offset, COLOR_RED,
                       COLOR_BLACK);

    static uint8_t w = 0;

    // Calculate offset
    uint8_t flag_len = 0;
    while (flag[flag_len++]) {
        // ...
    }

    uint8_t flag_print_x_offset =
        (ILI9225_LCD_HEIGHT - flag_len * (char_width + 1)) >> 1;

    while (true) {
        const uint16_t cur_color =
            colors[color++ % (sizeof(colors) / sizeof(colors[0]))];
        for (uint8_t i = 0; flag[i]; i++) {
            Display::draw_char(flag[i],
                               flag_print_x_offset + (char_width + 1) * i,
                               80 + sin_offsets[(i + w) % sizeof(sin_offsets)] +
                                   model_y_offset,
                               cur_color, COLOR_BLACK);
        }

        Display::fill_box(flag_print_x_offset, 70 + model_y_offset,
                          flag_print_x_offset + flag_len * (char_width + 1),
                          90 + char_height + model_y_offset, COLOR_BLACK);
        w++;
    }
}

void draw_centered(const char *txt, uint8_t y, uint16_t fg, uint16_t bg) {
    Display::draw_text(
        txt, (ILI9225_LCD_HEIGHT - (length(txt) * (char_width + 1))) >> 1, y,
        fg, bg);
}

void secret_developer_menu() {
    Display::clear(COLOR_BLACK);
    draw_centered("=== Developer Menu ===", 40 + model_y_offset, COLOR_GREEN,
                  COLOR_BLACK);
    draw_centered("Enter delta:", 40 + char_height + 1 + model_y_offset,
                  COLOR_GREEN, COLOR_BLACK);

    uint8_t delta[7] = {0};
    uint8_t idx = 0;
    char delta_buf[] = "0000000";
    constexpr char delta_txt_off =
        (ILI9225_LCD_HEIGHT - 7 * (char_width + 1)) >> 1;
    bool done = false;
    while (!done) {
        // 0 1 2 3 4 = LEFT UP DOWN RIGHT [OK]
        for (uint8_t i = 0; i < 7; i++) {
            delta_buf[i] = delta[i] + '0';
            Display::draw_char(
                delta_buf[i], delta_txt_off + i * (char_width + 1),
                70 + model_y_offset, (i == idx ? COLOR_ORANGE : COLOR_RED),
                COLOR_BLACK);
        }

        // Wait on update
        while (true) {
            if (Input::is_button_pressed(0)) {
                idx--;
                if (idx > 6) {
                    idx = 6;
                }
                break;
            } else if (Input::is_button_pressed(1)) {
                delta[idx]++;
                if (delta[idx] > 9) {
                    delta[idx] = 0;
                }
                break;
            } else if (Input::is_button_pressed(2)) {
                delta[idx]--;
                if (delta[idx] > 9) {
                    delta[idx] = 9;
                }
                break;
            } else if (Input::is_button_pressed(3)) {
                idx++;
                if (idx > 6) {
                    idx = 0;
                }
                break;
            } else if (Input::is_button_pressed(4)) {
                done = true;
                break;
            }
        }
    }

    uint32_t u_delta = 0;
    uint32_t m = 1;
    for (uint8_t i = 0; i < 7; i++) {
        u_delta += delta[6 - i] * m;
        m *= 10;
    }
    RNG::Bad::add_to_seed(u_delta);
}

} // namespace GUI
