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
#include "main.h"
#include "basic.h"
#include "game.h"
#include "res.h"

static const char *game_banner = res_game_banner;
static uint64_t *game_scoreboard = scoreboard;
static char (*game_names)[32] = names;

void show_winner(const char *winner) {
  print("WINNER: ");
  puts(winner);
}

bool readline(void *buf, size_t sz) {
  uint8_t *dst = buf;
  for (size_t i = 0; i < sz - 1; i++) {
    int ch = getchar();
    if (ch >= 0 && ch <= 0xff) {
      if (ch == '\n') {
        dst[i] = '\0';
        return true;
      }
      dst[i] = ch;
    } else {
      return false;
    }
  }

  dst[sz - 1] = '\0';
  return true;
}

void show_banner(void) {
  puts(game_banner);
}

void see_full_scoreboard(void) {
  puts("-=*) SCOREBOARD:\n");
  for (int i = 0; i < PLAYER_COUNT; i++) {
    char num[32] = {0};
    u64toa(num, i);
    print("  ");
    print(num);
    print(". ");
    u64toa(num, game_scoreboard[i]);
    print(num);
    print("pts --- ");
    puts(game_names[i]);
  }
}

void see_scoreboard(void) {
  puts("Which place's score do you want to see (0-9)?");
  char line[32];
  if (!readline(line, 32)) {
    return;
  }

  uint64_t player_idx = atou64(line);
  print("To get this place you need to beat this score: ");

  char num[32] = {0};
  u64toa(num, game_scoreboard[player_idx]);
  puts(num);
}

void shift_scoreboard(int place) {
  for (int i = PLAYER_COUNT - 1; i > place; i--) {
    game_scoreboard[i] = game_scoreboard[i - 1];
    strcpy(game_names[i], game_names[i - 1]);
  }
}

void get_player_name(int place) {
  char player_name[32] = {0};
  uint64_t len;

  puts("Congratulations! You're going to the SCOREBOARD!");
  puts("How long is your name (0-31)?");
  char line[16];
  if (!readline(line, 16)) {
    return;
  }
  len = atou64(line);

  if (len > 31) {
    puts("Name too long! No SCOREBOARD for you.");
  }

  puts("Now type in your name:");
  read(0, player_name, len);

  player_name[31] = '\0';
  strcpy(game_names[place], player_name);
}

void check_scoreboard(uint64_t score) {
  for (int i = 0; i < PLAYER_COUNT; i++) {
    if (score > game_scoreboard[i]) {
      shift_scoreboard(i);
      get_player_name(i);
      game_scoreboard[i] = score;
      return;
    }
  }
}

void game(void) {
  puts("Have Fun, Good Luck!");

  uint64_t score = 0;
  uint64_t round = 1;
  for (;;) {
    char num[32];

    print("\nRound ");
    u64toa(num, round);
    puts(num);

    uint8_t a = rand() % 10;
    uint8_t b = rand() % 10;
    uint8_t res = a + b;
    print("How much is ");
    u64toa(num, a);
    print(num);
    print(" + ");
    u64toa(num, b);
    print(num);
    puts(" ?");

    char line[32];
    if (!readline(line, 32)) {
      return;
    }
    uint8_t player_res = atou64(line);
    if (res != player_res) {
      puts("Wrong! Game Over!");
      break;
    }

    score += 5;
    print("Yes! +5pts! You have ");
    u64toa(num, score);
    print(num);
    puts("pts total.");
    round++;
  }

  check_scoreboard(score);
}

bool menu(void) {
  puts(
      "\n"
      "-=*) MAIN MENU:\n"
      "  1) Play The Game\n"
      "  2) See full scoreboard\n"
      "  3) See score for place\n"
      "  4) Exit\n"
      "Your choice?"
  );

  char line[32];
  if (!readline(line, 32)) {
    return false;
  }

  uint8_t choice = atou64(line);
  switch (choice) {
    case 1:
      game();
      return true;

    case 2:
      see_full_scoreboard();
      return true;

    case 3:
      see_scoreboard();
      return true;

    case 4:
      puts("Alright, bye");
      return false;
  }

  puts("Come again?");
  return true;
}
