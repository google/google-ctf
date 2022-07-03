// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include <stdint.h>
#include "main.h"
#include "game.h"

uint64_t scoreboard[PLAYER_COUNT] = {
    95,
    90,
    85,
    80,
    75,
    70,
    65,
    60,
    55,
    50
};

char names[PLAYER_COUNT][32] = {
    "Gary",
    "Yoel",
    "Nicholas",
    "Vanessa",
    "Alice",
    "Elizabeth",
    "Linda",
    "Peter",
    "Wayne",
    "Natalie",
};

static const char *winner = names[0];

int main(void) {
  show_banner();
  while (menu()) {}

  show_winner(winner);

  return 0;
}
