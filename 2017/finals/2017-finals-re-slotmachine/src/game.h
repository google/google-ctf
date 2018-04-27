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

#include "item.h"

namespace Game {
class Game {
  public:
    Game()
        : current_state{{Item::None, Item::None, Item::None},
                        {Item::None, Item::None, Item::None},
                        {Item::None, Item::None, Item::None}},
          current_points(100), current_bet(5) {
        redraw();
    };
    void spin();
    void change_bet();
    void redraw();

  private:
    void check_for_win();

    Item::type_t current_state[3][3];
    uint16_t current_points;

    uint8_t current_bet;
};
} // namespace Game
