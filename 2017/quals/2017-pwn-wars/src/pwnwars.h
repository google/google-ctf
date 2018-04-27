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



/*
 ============================================================================
 Name        : pwnwars.h
 Author      : Steven Vittitoe (scvitti@)
 Version     : 0.1
 ============================================================================
 */

#ifndef _PWNWARS_INC
#define _PWNWARS_INC

#include "ctflib.h"

unsigned short svc_port = 4547;
const char * svc_user = "pwnwars";

#define BANNER "[========================]\n"\
             "[         PWN WARS       ]\n"\
             "[========================]\n"

#define MAIN_MENU "What would you like to do?\n"\
              "    1. Tunnel\n"\
              "    2. Buy\n"\
              "    3. Sell\n"\
              "    4. Cold Storage\n"\
              "    5. Loan\n"\
              "    6. Sleep\n"\
              "    7. Inventory\n"\
              "    8. Quit\n\n"

#define GAME_DAYS 30
#define ACTIONS_PER_DAY 3
#define NUM_EXPLOITS 14

typedef struct _exploits {
  union {
    unsigned short val;
    struct {
      int win_local:1;
      int ie:1;
      int firefox:1;
      int chrome:1;
      int linux_local:1;
      int win_remote:1;
      int linux_remote:1;
      int openssh:1;
      int cisco:1;
      int lastpass:1;
      int android:1;
      int iOS:1;
      int osx:1;
      int rubber_hose:1;
    };
  };
} exploits;

typedef struct _defenses {
  union {
    unsigned short val;
    struct {
      int av:1;
      int firewall:1;
      int stack_cookies:1;
      int heap_segmentation:1;
      int sandbox:1;
    };
  };
} defenses;

typedef struct _items {
  int win_local;
  int ie;
  int firefox;
  int chrome;
  int linux_local;
  int win_remote;
  int linux_remote;
  int openssh;
  int cisco;
  int lastpass;
  int android;
  int iOS;
  int osx;
  int rubber_hose;
  int av;
  int firewall;
  int stack_cookies;
  int heap_segmentation;
  int sandbox;
} items;

items gPrices;

typedef struct _player {
  unsigned int sock;
  char name[128];
  unsigned long long location;
  unsigned int money;
  unsigned int offense;
  unsigned int defense;
  unsigned int loan;
  unsigned int storage;
  int hp;
  unsigned int day;
  unsigned int actions;
  items item_list;
} player;

struct _location {
  int number;
  const char * string;
  exploits exp;
  defenses def;
};

struct _location locations[] = {
    {0, "Underground", {{0}}, {{0}}},
    {1, "Cyberia", {{0}}, {{0}}},
    {2, "Metaverse", {{0}}, {{0}}},
    {3, "Scriptkiddie Garden", {{0}}, {{0}}},
    {4, "Sandbox Park", {{0}}, {{0}}},
    {5, "Data Haven", {{0}}, {{0}}}
};

int main(void);
int play_game(int client_fd);
const char * location_to_string(unsigned int loc);
void refresh_day(player * p);
int send_exploit_list(player * p);
int send_defense_list(player * p);
void send_stats(player * p);
void do_tunnel(player * p);
void do_buy(player * p);
void do_sell(player * p);
void do_cold_storage(player * p);
void do_loan(player * p);
void do_sleep(player * p);
void do_inventory(player * p);
void do_winner(player * p);
void update_player_off_def(player * p);
void do_fed_raid(player * p);
void do_loan_shark(player * p);
#endif
