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



#include "game.h"
#include "ILI9225.h"
#include "gui.h"
#include "item.h"
#include "rng.h"

#include <avr/interrupt.h>
#include <avr/wdt.h>
#include <util/delay.h>

namespace Game {

// Defines the y positions for each colon for a given bet
constexpr uint8_t bet_to_y_positions[][3] = {{0, 0, 0}, // unused. can't bet 0
                                             {1, 1, 1}, {0, 0, 0}, {2, 2, 2},
                                             {0, 1, 2}, {2, 1, 0}};

void Game::change_bet() {
    current_bet++;
    if (current_bet > 5) {
        current_bet = 1;
    }
    GUI::set_bet(current_bet);
}

void Game::spin() {
    if (current_points < current_bet) {
        // Game over
        cli();
        asm volatile("rjmp 0");
    }
    current_points -= current_bet;
    GUI::set_points(current_points);

    // Calculate new state
    current_state[0][0] = Item::get_random();
    current_state[0][1] = Item::get_random();
    current_state[0][2] = Item::get_random();

    current_state[1][0] = Item::get_random();
    current_state[1][1] = Item::get_random();
    current_state[1][2] = Item::get_random();

    current_state[2][0] = Item::get_random();
    current_state[2][1] = Item::get_random();
    current_state[2][2] = Item::get_random();

    for (uint8_t i = 0; i < 3; i++) {
        GUI::spin_col(i, current_state[i]);
        _delay_ms(100);
    }

    check_for_win();
}

void Game::check_for_win() {
    uint8_t win_line = 0;
    Item::type_t win_item = Item::None;

    for (uint8_t b = current_bet; b > 0; b--) {
#define GETYPOS(x) bet_to_y_positions[b][x]
#define GET(x) current_state[x][GETYPOS(x)]
        if (GET(0) != 0 && GET(0) == GET(1) && GET(1) == GET(2)) {
            // We have a winner!
            for (uint8_t _ = 0; _ < 3; _++) {
                for (uint8_t n = 0; n < 3; n++) {
                    GUI::set_field(n, GETYPOS(n), Item::None);
                }
                _delay_ms(100);
                for (uint8_t n = 0; n < 3; n++) {
                    GUI::set_field(n, GETYPOS(n), GET(n));
                }
                _delay_ms(100);
            }

            // if the items have a higher value than the current maximum, pick
            // the new one.
            if (GET(0) > win_item) {
                win_item = GET(0);
                win_line = b;
            }
        }
#undef GET
#undef GETYPOS
    }

    // Add points (if applicable)
    if (win_item != Item::None) {
        current_points += Item::get_points(win_item);
        GUI::set_points(current_points);
    }

    // Check if we should trigger the jackpot screen
    if (win_line == 1 && win_item == Item::Triple) {
        return GUI::jackpot("{FLAG_II}");
    }
}

void Game::redraw() {
    GUI::set_points(current_points);
    GUI::set_bet(current_bet);
}
} // namespace Game
