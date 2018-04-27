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



#include <avr/interrupt.h>
#include <avr/io.h>
#include <avr/wdt.h>
#include <math.h>
#include <util/delay.h>
#include <util/twi.h>

#include "ILI9225.h"
#include "assets.h"
#include "dac.h"
#include "game.h"
#include "gui.h"
#include "i2c.h"
#include "input.h"
#include "pin_configuration.h"
#include "rng.h"
#include "spi.h"

constexpr uint8_t length(const char *str) {
    return *str ? length(str + 1) + 1 : 0;
}

constexpr char l1[] PROGMEM = "Loading bootloader...............";
constexpr char l2[] PROGMEM = "Initializing hardware............";
constexpr char l3[] PROGMEM = "Getting root in prod.............";
constexpr char l4[] PROGMEM = "Hacking the gibson...............";
constexpr char l5[] PROGMEM = "Petting cats......MEOW...........";
constexpr char l6[] PROGMEM = "Executing main payload...........";

const char *lines[] = {l1, l2, l3, l4, l5, l6};

constexpr uint8_t secret_button_combination[] = {0, 1, 0, 1, 4, 3, 4, 3, 2};
constexpr uint8_t secret_dev_combination[] = {4, 3, 2, 1, 0, 1, 2, 3, 4};
constexpr uint8_t secret_button_combination_length =
    sizeof(secret_button_combination);
static_assert(sizeof(secret_dev_combination) ==
                  secret_button_combination_length,
              "Fix your code");

int main() {
    static uint8_t buttons_pressed_idx = 0;
    uint8_t buttons_pressed[secret_button_combination_length] = {0};
    cli();

    I2C::init();
    Input::init();
    SPI::init();
    // Display requires SPI
    Display::init();
    Display::clear();

    RNG::Good::init();
    // Enable interrupts
    sei();

    // Show some very important messages + initialize the bad RNG in the
    // meantime
    uint32_t seed = 0;
    for (int i = 0; i < 6; i++) {
        Display::draw_text_pgm(lines[i], 0,
                               i * (char_height + 1) + GUI::model_y_offset,
                               COLOR_WHITE);
        seed ^= RNG::Good::get_u8();
        seed = (seed << 6) | (seed >> 26);
        _delay_ms(70);
        Display::draw_text("[OK]", length(l1) * (char_width + 1),
                           i * (char_height + 1) + GUI::model_y_offset,
                           COLOR_GREEN);
        _delay_ms(30);
    }
    _delay_ms(200);

    RNG::Bad::seed(seed);

    Display::clear(GUI::background_color);
    Assets::draw_background();

    Game::Game game;

    // Button testing code
#if 0
    uint8_t state[5] = {};
    while (true) {
        constexpr uint8_t px_size = 10;
        for (uint8_t i = 0; i < 5; i++) {
            uint8_t px = i * px_size;
            if (Input::is_button_pressed(i)) {
                state[i] ^= 1;
            }
            if (state[i]) {
                Display::fill_box(0, px + 5, px_size, px + px_size, COLOR_WHITE);
            } else {
                Display::fill_box(0, px + 5, px_size, px + px_size, COLOR_DARKBLUE);
            }
        }
    }
#endif

    while (true) {
        if (Input::is_bet_pressed()) {
            buttons_pressed[buttons_pressed_idx++] = 0;
            game.change_bet();
        } else if (Input::is_spin_pressed()) {
            buttons_pressed[buttons_pressed_idx++] = 1;
            game.spin();
        } else if (Input::is_button_pressed(2)) {
            buttons_pressed[buttons_pressed_idx++] = 2;
        } else if (Input::is_button_pressed(3)) {
            buttons_pressed[buttons_pressed_idx++] = 3;
        } else if (Input::is_button_pressed(4)) {
            buttons_pressed[buttons_pressed_idx++] = 4;
        }

        if (buttons_pressed_idx == secret_button_combination_length) {
            buttons_pressed_idx = 0;
            bool is_flag_combi = true;
            bool is_dev_combi = true;

            for (uint8_t i = 0; i < secret_button_combination_length; i++) {
                if (buttons_pressed[i] != secret_button_combination[i]) {
                    is_flag_combi = false;
                }
                if (buttons_pressed[i] != secret_dev_combination[i]) {
                    is_dev_combi = false;
                }
            }
            if (is_flag_combi) {
                GUI::jackpot("{FLAG_I}");
            } else if (is_dev_combi) {
                GUI::secret_developer_menu();
                Display::clear(GUI::background_color);
                Assets::draw_background();
                game.redraw();
            }
        }
    }
}
