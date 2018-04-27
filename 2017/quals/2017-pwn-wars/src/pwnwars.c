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
 Name        : pwnwars.c
 Author      : Steven Vittitoe (scvitti@)
 Version     : 0.1
 ============================================================================
 */

#include "pwnwars.h"

int main(void) {
  int server_sock = init(svc_port);
  drop_privs_user(svc_user);
  loop(server_sock, play_game);
  return EXIT_SUCCESS;
}

int play_game(int sock) {
  player * p = (player *) malloc(sizeof(player));
  memset(p, 0, sizeof(player));
  p->sock = sock;
  p->money = 1000;
  p->hp = 100;
  p->location = 0;

  sendMsg(sock, BANNER, 0);

  while (p->day < GAME_DAYS)
  {
    refresh_day(p);
    p->actions = 0;
    while (p->actions < ACTIONS_PER_DAY)
    {
      sendMsg(sock, MAIN_MENU, 0);
      send_stats(p);
      if (p->hp <= 0) {
        sendMsg(sock, "You're toast.\n", 0);
        exit(0);
      }
      sendMsg(sock, "Choice: ", 0);
      switch(get_choice(sock, 1, 8)) {
        case 1:
          do_tunnel(p);
          break;
        case 2:
          do_buy(p);
          break;
        case 3:
          do_sell(p);
          break;
        case 4:
          do_cold_storage(p);
          break;
        case 5:
          do_loan(p);
          break;
        case 6:
          do_sleep(p);
          p->actions = ACTIONS_PER_DAY;
          break;
        case 7:
          do_inventory(p);
          p->actions--;
          break;
        case 8:
          sendMsg(sock, "Goodbye cruel world.\n", 0);
          exit(0);
        default:
          continue;
      }
      p->actions++;
    }
    sendMsg(sock, "\nAnother day has booted.\n", 0);
    p->day++;
  }
  sendMsg(sock, "\nGame Over.\n\n", 0);
  return 0;
}

void refresh_day(player * p) {
  int i = 0;
  unsigned short def;
  unsigned short exp;
  for (; i < sizeof(locations)/sizeof(locations[0]); i++) {
    def = get_random_int(0,0xffff);
    exp = get_random_int(0,0xffff);
    exp &= 0b0011111101111111; // never sell OpenSSH 0-day!
    memcpy(&locations[i].exp, &exp, sizeof(exp));
    memcpy(&locations[i].def, &def, sizeof(def));
  }
  gPrices.win_local = get_random_int(15000, 50000);
  gPrices.ie = get_random_int(30000, 150000);
  gPrices.firefox = get_random_int(1500, 50000);
  gPrices.chrome = get_random_int(200000, 500000);
  gPrices.linux_local = get_random_int(2000, 75000);
  gPrices.win_remote = get_random_int(150000, 1000000);
  gPrices.linux_remote = get_random_int(200000, 1500000);
  gPrices.openssh = get_random_int(1000000, 2500000);
  gPrices.cisco = get_random_int(2000, 5000);
  gPrices.lastpass = get_random_int(25, 500);
  gPrices.android = get_random_int(1000, 200000);
  gPrices.iOS = get_random_int(400000, 800000);
  gPrices.osx = get_random_int(500, 50000);
  gPrices.rubber_hose = get_random_int(5, 10);
  gPrices.av = get_random_int(20, 500);
  gPrices.firewall = get_random_int(5000, 15000);
  gPrices.stack_cookies = get_random_int(100, 12000);
  gPrices.heap_segmentation = get_random_int(1000, 5000);
  gPrices.sandbox = get_random_int(10000, 50000);

  if (p->offense > 0x313370 && p->defense > 0x31337) {
    for (i=0;i<sizeof(p->item_list)/sizeof(int); i++) {
      if (((int *) &p->item_list)[i] == 0) {
        break;
      }
    }
    if (i == sizeof(p->item_list)/sizeof(int)) {
      do_winner(p);
    }
  }

  if (get_random_int(0,99) < 10) {
    do_fed_raid(p);
  }

  if (get_random_int(0,99) > 90) {
    do_loan_shark(p);
  }
}

void do_fed_raid(player * p) {
  int num_feds = get_random_int(1,25);
  int damage = get_random_int(1,4) * num_feds;
  sendMsg(p->sock, "The fedz are on your tail!\n", 0);
  sendFormat(p->sock, "Officer hard-ass and his %d g-men ", num_feds);
  switch(get_random_int(0,3)){
    case 0:
      if (p->defense > 10000) {
        damage /= 2;
      }
      if (p->defense > 100000) {
        damage /= 2;
      }
      if (p->defense > 1000000) {
        damage /= 2;
      }
      sendFormat(p->sock, "open fire dealing %d damage!\n", damage);
      p->hp -= damage;
      break;
    case 1:
      sendFormat(p->sock, "confiscate all your warez!\n");
      memset(&p->item_list, 0, sizeof(p->item_list));
      p->offense = 0;
      p->defense = 0;
      break;
    case 2:
      sendFormat(p->sock, "steal all your pwncoin!\n");
      p->money = 0;
      break;
    case 3:
      sendFormat(p->sock, "take shots at you but miss.\n");
      break;
  }
  if (p->hp <= 0) {
    return;
  }
  sendMsg(p->sock, "Do you run or fight?\n    1. Run\n"
      "    2. Fight\nChoice: ", 0);
  int choice = get_choice(p->sock, 1, 2);
  if (choice == 1) {
    if (get_random_int(0,99) < 75) {
      sendMsg(p->sock, "You successfully evade the fedz, this time.\n", 0);
      return;
    } else {
      sendMsg(p->sock, "You try to escape but hit a tripwire and fail.\n", 0);
      choice = 2;
    }
  }
  if (choice == 2) {
    sendFormat(p->sock, "You attack officer hard-ass and his %d g-men with %d "
        "bits of exploitation prowess.\n", num_feds, p->offense);
    if ((num_feds * 1000) > p->offense) {
      sendFormat(p->sock, "Your attack is no match for the fedz opsec.\n");
      do_fed_raid(p);
    } else {
      int found = get_random_int(1,1000000);
      sendFormat(p->sock, "You pwned the fedz and halt their attack\n"
              "You found %d pwncoin in their wallets\n", found);
      p->money += found;
      return;
    }
  }
}

void do_loan_shark(player * p) {
  if (p->loan == 0) {
    return;
  }
  unsigned int collect = get_random_int(1, p->loan);
  sendFormat(p->sock, "Loan shark has come to collect %d pwncoin!\n", collect);
  if (p->money < collect) {
    sendFormat(p->sock, "You cover the debt with your kneecaps.\n");
    int hp_loss = p->hp/2;
    if (hp_loss < 10)
      hp_loss = 10;
    p->hp = hp_loss;
    p->loan -= collect;
  } else {
    sendFormat(p->sock, "You pay the entire amount.\n");
    p->money -= collect;
    p->loan -= collect;
  }

}

void do_winner(player * p) {
  if (strlen(p->name) == 0) {
    sendMsg(p->sock, "What be thy handle: ", 0);
    read_until_delim(p->sock, p->name, sizeof(p->name)-1, '\n');
    sendFormat(p->sock, p->name);
    sendMsg(p->sock, ", congratulations you are an epic hax0r!\n", 0);
  }
}

void send_stats(player * p) {
  sendFormat(p->sock, "[hp: %d/100, def: %d, off: %d,"
      " pwncoin: %d (%d), loc: %s, day: %d/%d]\n", p->hp, p->defense,
      p->offense, p->money, p->loan, location_to_string(p->location),
      p->day, GAME_DAYS);
}

const char * location_to_string(unsigned int loc) {
  int i = 0;
  for (; i < sizeof(locations)/sizeof(locations[0]); i++) {
    if (loc == locations[i].number) {
      return locations[i].string;
    }
  }
  return "Unknown cyber-ether";
}

void do_tunnel(player * p) {
  int location;
  int i = 0;
  sendMsg(p->sock, "What site do you wish to tunnel to?\n", 0);
  for (; i < sizeof(locations)/sizeof(locations[0]); i++) {
    sendFormat(p->sock, "    %d. %s\n", locations[i].number,
               locations[i].string);
  }
  sendFormat(p->sock, "    %d. Back\n", i);
  sendMsg(p->sock, "Choice: ", 0);
  location = get_choice(p->sock, 0, sizeof(locations) / sizeof(locations[0])+1);
  if (location == i) {
    p->actions--;
    return;
  }
  sendFormat(p->sock, "Slip stream tunnel engaged to: %s\n",
             location_to_string(location));
  p->location = location;
}

void do_buy(player * p) {
  unsigned int choice = 0;
  int off_choice = -1;
  unsigned int off_choice_max = 0;
  int def_choice = -1;
  unsigned int def_choice_max = 0;
  unsigned int i = 0;
  unsigned int bitoffset = 0;
  unsigned int price = 0;
  unsigned int off_buy_amount = 0;
  unsigned int def_buy_amount = 0;
  while (choice != 3) {
    sendMsg(p->sock, "What do you want to buy?\n    1. Exploits\n    2. Defense"
        "\n    3. Back\n\nChoice: ", 0);
    choice = get_choice(p->sock, 1, 3);

    if (choice == 1) {
      sendFormat(p->sock, "The following exploits are for sale in the %s:\n",
                 location_to_string(p->location));
      off_choice_max = send_exploit_list(p);
      send_stats(p);
      sendMsg(p->sock, "Choice: ", 0);
      off_choice = get_choice(p->sock, 1, off_choice_max);
      if (off_choice == off_choice_max) {
        continue;
      }
      i = 0;
      bitoffset = 0;
      if (off_choice > off_choice_max || off_choice < 1) {
        continue;
      }
      while (i != off_choice) {
        if ((locations[p->location].exp.val) & (1<<bitoffset)) {
          i++;
        }
        bitoffset++;
      }
      price = (int)*(((int*)&gPrices)+bitoffset-1);
      sendFormat(p->sock, "You can buy %d of these exploits at %d each.\n"
          "How many would you like to buy: ", p->money/price, price);
      off_buy_amount = get_choice(p->sock, 0, p->money/price);
      if ((off_buy_amount * price) > p->money) {
        continue;
      } else {
        p->money = p->money - (off_buy_amount * price);
        int * item_ptr = ((int*)&p->item_list+bitoffset-1);
        *item_ptr += off_buy_amount;
        update_player_off_def(p);
      }
    }

    if (choice == 2) {
      sendFormat(p->sock, "The following defenses are for sale in the %s:\n",
                 location_to_string(p->location));
      def_choice_max = send_defense_list(p);
      send_stats(p);
      sendMsg(p->sock, "Choice: ", 0);
      def_choice = get_choice(p->sock, 1, def_choice_max);
      if (def_choice == def_choice_max) {
        continue;
      }
      i = 0;
      bitoffset = 0;
      if (def_choice > def_choice_max || def_choice < 1) {
        continue;
      }
      while (i != def_choice) {
        if ((locations[p->location].def.val) & (1<<bitoffset)) {
          i++;
        }
        bitoffset++;
      }
      price = (int)*(((int*)&gPrices)+NUM_EXPLOITS+bitoffset-1);
      sendFormat(p->sock, "You can buy %d of these defenses at %d each.\n"
          "How many would you like to buy: ", p->money/price, price);
      def_buy_amount = get_choice(p->sock, 0, p->money/price);
      if ((def_buy_amount * price) > p->money) {
        continue;
      } else {
        p->money = p->money - (def_buy_amount * price);
        int * item_ptr = ((int*)&p->item_list+NUM_EXPLOITS+bitoffset-1);
        *item_ptr += def_buy_amount;
        update_player_off_def(p);
      }
    }
  }
}

int send_exploit_list(player * p) {
  int i = 1;
  if (locations[p->location].exp.win_local) {
    sendFormat(p->sock, "    %d. Windows local: %d (%d)\n", i,
               gPrices.win_local, p->item_list.win_local);
    i++;
  }
  if (locations[p->location].exp.ie) {
    sendFormat(p->sock, "    %d. Internet Explorer: %d (%d)\n", i,
               gPrices.ie, p->item_list.ie);
    i++;
  }
  if (locations[p->location].exp.firefox) {
    sendFormat(p->sock, "    %d. Firefox: %d (%d)\n", i,
               gPrices.firefox, p->item_list.firefox);
    i++;
  }
  if (locations[p->location].exp.chrome) {
    sendFormat(p->sock, "    %d. Chrome: %d (%d)\n", i,
               gPrices.chrome, p->item_list.chrome);
    i++;
  }
  if (locations[p->location].exp.linux_local) {
    sendFormat(p->sock, "    %d. Linux local: %d (%d)\n", i,
               gPrices.linux_local, p->item_list.linux_local);
    i++;
  }
  if (locations[p->location].exp.win_remote) {
    sendFormat(p->sock, "    %d. Windows remote: %d (%d)\n", i,
               gPrices.win_remote, p->item_list.win_remote);
    i++;
  }
  if (locations[p->location].exp.linux_remote) {
    sendFormat(p->sock, "    %d. Linux remote: %d (%d)\n", i,
               gPrices.linux_remote, p->item_list.linux_remote);
    i++;
  }
  if (locations[p->location].exp.openssh) {
    sendFormat(p->sock, "    %d. OpenSSH: %d (%d)\n", i, gPrices.openssh,
               p->item_list.openssh);
    i++;
  }
  if (locations[p->location].exp.cisco) {
    sendFormat(p->sock, "    %d. Cisco: %d (%d)\n", i, gPrices.cisco,
               p->item_list.cisco);
    i++;
  }
  if (locations[p->location].exp.lastpass) {
    sendFormat(p->sock, "    %d. LastPass: %d (%d)\n", i, gPrices.lastpass,
               p->item_list.lastpass);
    i++;
  }
  if (locations[p->location].exp.android) {
    sendFormat(p->sock, "    %d. Android: %d (%d)\n", i, gPrices.android,
               p->item_list.android);
    i++;
  }
  if (locations[p->location].exp.iOS) {
    sendFormat(p->sock, "    %d. iOS: %d (%d) \n", i, gPrices.iOS,
               p->item_list.iOS);
    i++;
  }
  if (locations[p->location].exp.osx) {
    sendFormat(p->sock, "    %d. OSX: %d (%d)\n", i, gPrices.osx,
               p->item_list.osx);
    i++;
  }
  if (locations[p->location].exp.rubber_hose) {
    sendFormat(p->sock, "    %d. Rubber hose: %d (%d)\n", i,
               gPrices.rubber_hose, p->item_list.rubber_hose);
    i++;
  }
  sendFormat(p->sock, "    %d. Back\n", i);
  return i;
}

int send_defense_list(player * p) {
  int i = 1;
  if (locations[p->location].def.av) {
    sendFormat(p->sock, "    %d. Antivirus: %d (%d)\n", i,
               gPrices.av, p->item_list.av);
    i++;
  }
  if (locations[p->location].def.firewall) {
    sendFormat(p->sock, "    %d. Firewall: %d (%d)\n", i,
               gPrices.firewall, p->item_list.firewall);
    i++;
  }
  if (locations[p->location].def.stack_cookies) {
    sendFormat(p->sock, "    %d. Stack Cookies: %d (%d)\n", i,
               gPrices.stack_cookies, p->item_list.stack_cookies);
    i++;
  }
  if (locations[p->location].def.heap_segmentation) {
    sendFormat(p->sock, "    %d. Heap Segmentation: %d (%d)\n", i,
               gPrices.heap_segmentation, p->item_list.heap_segmentation);
    i++;
  }
  if (locations[p->location].def.sandbox) {
    sendFormat(p->sock, "    %d. Sandbox: %d (%d)\n", i,
               gPrices.sandbox, p->item_list.sandbox);
    i++;
  }
  sendFormat(p->sock, "    %d. Back\n", i);
  return i;
}

void do_sell(player * p) {
  unsigned int choice = 0;
  int off_choice = -1;
  unsigned int off_choice_max = 0;
  int def_choice = -1;
  unsigned int def_choice_max = 0;
  unsigned int i = 0;
  unsigned int bitoffset = 0;
  unsigned int price = 0;
  unsigned int off_sell_amount = 0;
  unsigned int def_sell_amount = 0;
  int num_items = 0;
  while (choice != 3) {
    sendMsg(p->sock, "What do you want to sell?\n    1. Exploits\n    2. Defense"
        "\n    3. Back\n\nChoice: ", 0);
    choice = get_choice(p->sock, 1, 3);

    if (choice == 1) {
      sendFormat(p->sock, "You can sell the following exploits in %s:\n",
                 location_to_string(p->location));
      off_choice_max = send_exploit_list(p);
      send_stats(p);
      sendMsg(p->sock, "Choice: ", 0);
      off_choice = get_choice(p->sock, 1, off_choice_max);
      if (off_choice == off_choice_max) {
        continue;
      }
      i = 0;
      bitoffset = 0;
      if (off_choice > off_choice_max || off_choice < 1) {
        continue;
      }
      while (i != off_choice) {
        if ((locations[p->location].exp.val) & (1<<bitoffset)) {
          i++;
        }
        bitoffset++;
      }
      price = (int)*(((int*)&gPrices)+bitoffset-1);
      num_items = (int)*((int*)(&p->item_list)+bitoffset-1);
      sendFormat(p->sock, "You have %d of these exploits to sell.\n"
          "How many would you like to sell: ", num_items, price);
      off_sell_amount = get_choice(p->sock, 0, num_items);
      if (off_sell_amount > num_items) {
        continue;
      } else {
        p->money = p->money + (off_sell_amount * price);
        int * item_ptr = ((int*)&p->item_list+bitoffset-1);
        *item_ptr -= off_sell_amount;
        update_player_off_def(p);
      }
    }

    if (choice == 2) {
      sendFormat(p->sock, "You can sell the following defenses in %s:\n",
                 location_to_string(p->location));
      def_choice_max = send_defense_list(p);
      send_stats(p);
      sendMsg(p->sock, "Choice: ", 0);
      def_choice = get_choice(p->sock, 1, def_choice_max);
      if (def_choice == def_choice_max) {
        continue;
      }
      i = 0;
      bitoffset = 0;
      if (def_choice > def_choice_max || def_choice < 1) {
        continue;
      }
      while (i != def_choice) {
        if ((locations[p->location].def.val) & (1<<bitoffset)) {
          i++;
        }
        bitoffset++;
      }
      price = (int)*(((int*)&gPrices)+NUM_EXPLOITS+bitoffset-1);
      num_items = (int)*((int*)(&p->item_list)+NUM_EXPLOITS+bitoffset-1);
      sendFormat(p->sock, "You have %d of these defenses to sell.\n"
          "How many would you like to sell: ", num_items, price);
      def_sell_amount = get_choice(p->sock, 0, p->money/price);
      if (def_sell_amount > num_items) {
        continue;
      } else {
        p->money = p->money + (def_sell_amount * price);
        int * item_ptr = ((int*)&p->item_list+NUM_EXPLOITS+bitoffset-1);
        *item_ptr -= def_sell_amount;
        update_player_off_def(p);
      }
    }
  }
}

void update_player_off_def(player * p) {
  p->offense = 0;
  p->defense = 0;
  p->offense += p->item_list.win_local * 100;
  p->offense += p->item_list.ie * 50;
  p->offense += p->item_list.firefox * 150;
  p->offense += p->item_list.chrome * 1000;
  p->offense += p->item_list.win_remote * 1500;
  p->offense += p->item_list.linux_remote * 3000;
  p->offense += p->item_list.openssh * 10000000;
  p->offense += p->item_list.cisco * 100;
  p->offense += p->item_list.lastpass * 10;
  p->offense += p->item_list.android * 75;
  p->offense += p->item_list.iOS * 5000;
  p->offense += p->item_list.osx * 500;
  p->offense += p->item_list.rubber_hose;
  p->defense += p->item_list.av * 100;
  p->defense += p->item_list.firewall * 1000;
  p->defense += p->item_list.stack_cookies * 75;
  p->defense += p->item_list.heap_segmentation * 800;
  p->defense += p->item_list.sandbox * 10000;
}
void do_cold_storage(player * p) {
  sendMsg(p->sock, "Would you like to:\n    1. Add\n    2. Withdraw\n"
          "    3. Back", 0);
  int choice = get_choice(p->sock, 1, 3);
  if (choice == 1) {
    sendFormat(p->sock, "You currently have %d in cold storage.\nHow much would you"
            " like to add: ", p->storage);
    unsigned int storage = get_choice(p->sock, 0, p->money);
    if (storage > p->money) {
      return;
    }
    p->money -= storage;
    p->storage += storage;
  }

  if (choice == 2) {
    sendFormat(p->sock, "You currently have %d in cold storage.\nHow much would you"
            " like to withdraw: ", p->storage);
    unsigned int storage = get_choice(p->sock, 0, p->storage);
    if (storage > p->storage) {
      return;
    }
    p->money += storage;
    p->storage -= storage;
  }
}

void do_loan(player * p) {
  long loan_amount = get_random_int(0, 1000);
  long pay_back = 0;
  long borrow_amount = 0;
  long percentage = 0;
  loan_amount *= (p->day+1);
  percentage = get_random_int(1,60);
  pay_back = loan_amount + (percentage*loan_amount)/100;
  if (p->loan > 0) {
    sendMsg(p->sock, "Would you like to repay the loan shark?\n"
            "    1. Yes\n    2. No\nChoice: ", 0);
    int repay = get_choice(p->sock, 1, 2);
    if (repay == 1) {
      sendMsg(p->sock, "How much would you like repay: ", 0);
      int repay_amount = get_choice(p->sock, 0, p->money);
      if (repay_amount < (int) p->money) {
        p->loan -= repay_amount;
        p->money -= repay_amount;
      }
    }

  }
  sendFormat(p->sock, "Loan shark offers you %d pwncoin if you pay back %d"
             " pwncoin (%d%%)\n", loan_amount, pay_back, percentage);
  sendMsg(p->sock, "How much would you like to borrow: ", 0);
  borrow_amount = get_choice(p->sock, 0, loan_amount);
  if (borrow_amount > loan_amount) {
    return;
  }

  p->loan += borrow_amount + ((borrow_amount * percentage)/100);
  p->money += borrow_amount;

}

void do_sleep(player * p) {
  switch(get_random_int(0,4)) {
    case 0:
      sendMsg(p->sock, "Entering hibernation mode\n", 0);
      break;
    case 1:
      sendMsg(p->sock, "Hard disks spinning down\n", 0);
      break;
    case 2:
      sendMsg(p->sock, "Initiating reboot\n", 0);
      break;
    case 3:
      sendMsg(p->sock, "Zzzzzzzzzzzzzz\n", 0);
      break;
    case 4:
      sendMsg(p->sock, "Halting\n", 0);
      break;
  }
  sleep(1);
}

void do_inventory(player * p) {
  sendFormat(p->sock, "=[ %s Inventory ]=\n", p->name);
  sendFormat(p->sock, "  Offense:              %d\n"
             "    Windows Locals:     %d\n"
             "    Internet Explorer:  %d\n"
             "    Firefox:            %d\n"
             "    Chrome:             %d\n"
             "    Linux Locals:       %d\n"
             "    Windows Remotes:    %d\n"
             "    Linux Remotes:      %d\n"
             "    OpenSSH:            %d\n"
             "    Cisco:              %d\n"
             "    LastPass:           %d\n"
             "    Android:            %d\n"
             "    iOS:                %d\n"
             "    OSX:                %d\n"
             "    Rubber Hose:        %d\n"
             "  Defense:              %d\n"
             "    Antivirus:          %d\n"
             "    Firewalls:          %d\n"
             "    Stack Cookies:      %d\n"
             "    Heap Segmentation:  %d\n"
             "    Sandboxes:          %d\n",
             p->offense, p->item_list.win_local, p->item_list.ie,
             p->item_list.firefox, p->item_list.chrome,
             p->item_list.linux_local, p->item_list.win_remote,
             p->item_list.linux_remote, p->item_list.openssh,
             p->item_list.cisco, p->item_list.lastpass,
             p->item_list.android, p->item_list.iOS, p->item_list.osx,
             p->item_list.rubber_hose, p->defense, p->item_list.av,
             p->item_list.firewall, p->item_list.stack_cookies,
             p->item_list.heap_segmentation, p->item_list.sandbox);
}
