// Copyright 2024 Google LLC
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
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>


void entry();
void _entry();
void end_of_encrypted();

__attribute__((section("encrypted"), aligned(4096))) void entry() {
  _entry();
}

#define ENC __attribute__((section("encrypted")))

#define say(fmt, ...) { const char local_fmt[] = fmt; printf(local_fmt, ##__VA_ARGS__); }

typedef struct item {
  char name[256];
  int atk;
  int def;
} item;

typedef struct player {
  char name[256];
  int atk;
  int def;
  int toughness; // *10 = max hp
  int hp;
  int gold;
  int time;
  item items[10];
} player;

typedef struct state {
  int x, y, prevx, prevy;
} state;

ENC int hour(int time) {
  return 8 + time / 60;
}

ENC int minute(int time) {
  return time % 60;
}

ENC void go(state* s, player* p) {
  p->time += 15;
  while (1) {
    say("What do you want to do? *NORTH *SOUTH *WEST *EAST *INVENTORY\n");
    char what[256];
    scanf("%s", what);
    char cmds[5][16] = {"NORTH", "SOUTH", "WEST", "EAST", "INVENTORY"};
    int dx = 0;
    int dy = 0;

    if (!strcmp(what, cmds[0])) {
      dy = -1;
    }
    if (!strcmp(what, cmds[1])) {
      dy = 1;
    }
    if (!strcmp(what, cmds[2])) {
      dx = -1;
    }
    if (!strcmp(what, cmds[3])) {
      dx = 1;
    }
    if (dx != 0 || dy != 0) {
      s->prevx = s->x;
      s->prevy = s->y;
      s->x += dx;
      s->y += dy;
      say("You go there.\n");
      break;
    }
    if (!strcmp(what, cmds[4])) {
      say("You look in your backpack...\n");
      int anything = 0;
      for (int i = 0; i < 10; i++) {
        if (p->items[i].name[0]) {
          say("%d. %s\n", i+1, p->items[i].name);
          anything = 1;
        }
      }
      if (!anything) {
        say("It's empty.\n");
      }
      continue;
    }
    say("What?\n");
  }
}

ENC void back(state* s) {
  say("You go back...\n");
  s->x = s->prevx;
  s->y = s->prevy;
}

ENC void shop(player* p) {
  say("You walk into a tiny shop. A man behind the counter shows you some items for sale.\n");
  say("'Hey %s, long time no see. How can I help ya?'", p->name);
  while (1) {
    item items[] = {{"Sword", 3, 0}, {"Shield", 0, 3}, {"Boat", 0, 0}};
    int prices[] = {200, 100, 1337};
    for (int i = 0; i < sizeof(prices)/sizeof(prices[0]); i++) {
      say("%d. %s ($%d)\n", i+1, items[i].name, prices[i]);
    }
    say("Do you want to buy something, or EXIT?\n");
    char cmd[256];
    scanf("%s", cmd);
    char exit[] = "EXIT";
    if (!strcmp(cmd, exit)) {
      say("You walk out.\n");
      break;
    }
    int anything = 0;
    for (int i = 0; i < sizeof(prices)/sizeof(prices[0]); i++) {
      if (!strcmp(cmd, items[i].name)) {
        anything = 1;
        if (p->gold < prices[i]) {
          say("That's too expensive.\n");
          continue;
        }
        int have = 0;
        for (int j = 0; j < 10; j++) {
          if (!strcmp(cmd, p->items[j].name)) {
            have = 1;
          }
        }
        if (have) {
          say("You already have it.\n");
          continue;
        }
        p->gold -= prices[i];
        for (int j = 0; j < 10; j++) {
          if (p->items[j].name[0] == 0) {
            memcpy(&p->items[j], &items[i], sizeof(items[i]));
            break;
          }
        }
        say("You bought it.\n");
      }
    }
    if (!anything) {
      say("I'm afraid we don't sell that here.\n");
    }
  }
}

ENC void village(player* p) {
  say("You're in a small village. There are only a couple buildings there...\n");
}

ENC void home(player* p) {
  say("You dream of riches and flags in the temple... Then you wake up.\n");
  say("Your health is restored. It is now eight o'clock.\n");
  p->hp = 10 * p->toughness;
  p->time = 0;
}

ENC void mines(player* p) {
  say("You enter mines. You see fellow dwarves solving math problems to mine cryptogold.\n");
  while (1) {
    say("What do you do? *MINE *EXIT\n");
    char cmd[256];
    scanf("%s", cmd);
    char exit[] = "EXIT";
    char mine[] = "MINE";
    if (!strcmp(cmd, exit)) {
      break;
    }
    if (!strcmp(cmd, mine)) {
      int x = 1 + rand() % 100;
      int y = 1 + rand() % 100;
      int operation = rand() % 5;
      char ops[5][16] = {"plus", "minus", "times", "divided by", "modulo"};
      int z;
      switch (operation) {
        case 0: z = x + y; break;
        case 1: z = x - y; break;
        case 2: z = x * y; break;
        case 3: z = x / y; break;
        case 4: z = x % y; break;
      }
      say("What is %d %s %d?\n", x, ops[operation], y);
      int answer = 0;
      scanf("%d", &answer);
      if (answer == z) {
        int much = rand() % 5;
        say("The block of rock shatters; you gain %d gold.\n", much);
        p->gold += much;
      }
      else {
        say("Nope...\n");
      }
      continue;
    }
    say("What?\n");
  }
}

ENC void river(player* p, state* s) {
  say("You enter a river.\n");
  int have = 0;
  char boat[] = "Boat";
  for (int j = 0; j < 10; j++) {
    if (!strcmp(boat, p->items[j].name)) {
      have = 1;
    }
  }
  if (!have) {
    say("You quickly realize it's very deep and fast; you cannot swim across.\n");
    back(s);
  }
  else {
    say("Your boat works well.\n");
    go(s, p);
  }
}

ENC void status(player* p) {
  say("Status:\nATK: %d\nDEF: %d\nTGH: %d\nHP: %d\nGOLD: %d\nTIME: %02d:%02d\n----\n\n",
            p->atk, p->def, p->toughness, p->hp, p->gold, hour(p->time), minute(p->time));
}

ENC void fight(player* p) {
  int enemy_hp = 10 + rand() % 40;
  int enemy_atk = 1 + rand() % 3;
  int enemy_def = rand() % 3;
  int atk = p->atk;
  int def = p->def;
  for (int j = 0; j < 10; j++) {
    if (p->items[j].name[0]) {
      atk += p->items[j].atk;
      def += p->items[j].def;
    }
  }

  while (1) {
    status(p);
    say("Enemy: %d HP\n", enemy_hp);
    if (p->hp <= 0 || hour(p->time) >= 23) {
      say("You pass out. When you wake up, it's already the next day. You are penniless and have nothing in your pockets.\n");
      p->gold = 0;
      p->hp = 1;
      p->time = 0;
      for (int j = 0; j < 10; j++) {
        p->items[j].name[0] = 0;
      }
      break;
    }
    p->time += 10; // each round is 10 minutes.
    say("What do you do? *ATTACK *RUN *INSULT\n");
    char cmd[16];
    scanf("%s", cmd);
    char cmdattack[] = "ATTACK";
    char cmdrun[] = "RUN";
    char cmdinsult[] = "INSULT";
    if (!strcmp(cmd, cmdattack)) {
      int hit = atk - enemy_def;
      if (hit <= 0) hit = 1;
      enemy_hp -= hit;
      say("You hit the enemy.\n");
    }
    else if (!strcmp(cmd, cmdrun)) {
      if (rand() % 3 == 0) {
        say("You ran away.\n");
        break;
      }
      else {
        say("You try to run away but the bandit catches up with you.\n");
      }
    }
    else if (!strcmp(cmd, cmdinsult)) {
      say("You yell 'your aim is so bad you wouldn't hit a tree'. The bandit just laughs back.\n");
    }
    else {
      say("You accidentally trip and miss your opportunity to attack.\n");
    }
    if (enemy_hp <= 0) {
      say("The bandit collapses. You quickly look around and see nobody, then take their sack of gold.\n");
      p->gold += 10 + rand() % 100;
      break;
    }
    int hit = enemy_atk - def;
    if (hit <= 0) hit = 1;
    say("The bandit hits you with a fist.\n");
    p->hp -= hit;
  }
}

ENC void generic(player* p) {
  say("You are in the middle of a large field. Tall grass is everywhere.\n");
  if (rand() % 10 == 0) {
    say("A bandit ambushed you!\n");
    fight(p);
  }
}

void temple(player* p);

ENC void game(player* p) {
  char map[16][16] = {
    "wwwwwwwwwwwwwww",
    "w  vvv   mmmmmw",
    "w  vSvv   mmmmw",
    "w  vvHv    mmmw",
    "w   vvv    mmmw",
    "w          mmrw",
    "w           rrw",
    "w           r w",
    "w           r w",
    "w          rr w",
    "w          r  w",
    "w          r  w",
    "w        rrr  w",
    "w      rrr   mw",
    "w      r  T mmw",
    "wwwwwwwwwwwwwww",
  };
  // w - wall (impassable, afraid of getting lost)
  // S - Shop
  // v - village
  // H - Home
  // m - mines
  // r - river
  // T - temple
  say("TODO\n");
  state s;
  s.prevx = 5; s.prevy = 3; // Home
  s.x = 5; s.y = 3; // Home
  while (1) {
    if (hour(p->time) >= 23) {
      say("You feel very sleepy... You lie down on the ground and try to sleep until morning.\n");
      p->time = 0;
    }
    char c = map[s.y][s.x];
    say("\n");
    char tmp_map[16][16];
    memcpy(tmp_map, map, sizeof(map));
    tmp_map[s.y][s.x] = '@';
    for (int i = 0; i < 16; i++) {
      say("%s\n", tmp_map[i]);
    }
    status(p);

    switch (c) {
      case 'w':
        say("You feel that your destiny is not in this direction... Besides, you're afraid you'll get lost. You go back.\n");
        back(&s);
        break;
      case 'S':
        shop(p);
        go(&s, p);
        break;
      case 'v':
        village(p);
        go(&s, p);
        break;
      case 'H':
        home(p);
        go(&s, p);
        break;
      case 'm':
        mines(p);
        go(&s, p);
        break;
      case 'r':
        river(p, &s); // May go back if needed. Otherwise, go()
        break;
      case 'T':
        temple(p);
        go(&s, p);
        break;
      case ' ':
        generic(p);
        go(&s, p);
        break;
      default:
        say("Uhh, I think somethings wrong...\n");
        break;
    }
  }
}

ENC void _entry() {
  say("Welcome to our newest dungeon crawler!\n");
  say("First, what is your name?\n");
  player p;
  memset(&p, 0, sizeof(p));
  // It's reversing, don't worry about security...
  scanf("%s", p.name);
  while (1) {
    say("Now let's distribute your skill points.\n");
    say("You have 10 points, split into attack, defense and toughness.\n");
    say("What is your attack?\n");
    scanf("%d", &p.atk);
    say("What is your defense?\n");
    scanf("%d", &p.def);
    say("What is your toughness?\n");
    scanf("%d", &p.toughness);
    if (p.atk + p.def + p.toughness == 10 && p.atk > 0 && p.def > 0 && p.toughness > 0) {
      break;
    }
    say("Don't try to cheat!\n");
  }
  p.hp = 10 * p.toughness;
  p.gold = 50;
  say("OK, %s... the game is on!\n", p.name);
  game(&p);
}


#include <stdint.h>

uint64_t xstate;
#define FLAGLEN 47

typedef struct {
  uint64_t length, start, initial;
} len_start_init;

len_start_init array[100] = {

  {435, 9305783678484258834ULL, -54827},
{379, 12967555605360310577ULL, -44038},
{378, 6098263986074817589ULL, -45538},
{368, 12837287306472676772ULL, -45018},
{367, 1038964616528732630ULL, -44499},
{364, 4279714948553608498ULL, -46103},
{349, 13873419554154430002ULL, -44609},
{340, 7029191707039513964ULL, -43074},
{339, 50155436649781121ULL, -42657},
{334, 6059579259497464038ULL, -41092},
{333, 11204103842727427458ULL, -43444},
{331, 1483478577012402160ULL, -42859},
{331, 202732553533293053ULL, -39916},
{324, 10427128468330635219ULL, -41530},
{321, 3153716288308188898ULL, -42472},
{320, 9874938606840858589ULL, -38801},
{319, 17071518664643433021ULL, -40563},
{317, 14345255121859546870ULL, -40031},
{317, 6814610243231156897ULL, -40485},
{315, 12550197884389987214ULL, -41403},
{313, 3121673241969160658ULL, -38210},
{310, 8289668274864344936ULL, -40535},
{310, 2919897795054578491ULL, -42046},
{305, 5189047639225936336ULL, -38820},
{305, 2763912013546289040ULL, -41084},
{299, 11148083789371761746ULL, -40217},
{298, 1438883514136254188ULL, -39345},
{297, 1421959364127313125ULL, -38145},
{297, 567876130852348491ULL, -39599},
{296, 17889927348541229941ULL, -37226},
{294, 6685808541813025032ULL, -36730},
{293, 3543362376756601918ULL, -36696},
{291, 16294830690679673252ULL, -38266},
{289, 15553275663366151488ULL, -36951},
{288, 17408258050940276891ULL, -38397},
{287, 4273191070961503626ULL, -35804},
{287, 4063044802243826282ULL, -39385},
{285, 10350855087035894898ULL, -35295},
{283, 16412851595385751324ULL, -34456},
{283, 11750142138871628214ULL, -36196},
{280, 7067937301289863541ULL, -36707},
{279, 15926101817825757842ULL, -36723},
{279, 3987803928079197831ULL, -35318},
{279, 3390070921076296426ULL, -34301},
{279, 2972378816495387585ULL, -36971},
{279, 723909356187982078ULL, -35866},
{278, 13429121015235788182ULL, -36515},

    };
// Flag: CTF{l0oks_l1k3_x86p3rm_pr07ector_i5_n0t_5ecur3}

uint64_t xorshift64();
// A bit not satisfying hat it's not an encrypted function, but the challenge
// could be too hard otherwise.
int decrypt(char* flag) {
  const unsigned char* binary_data = (const unsigned char*) entry;
  int correct = 1;
  for (int i = 0; i < FLAGLEN; i++) {
    uint32_t sum = array[i].initial;
    xstate = array[i].start;
    int length = array[i].length;
    for (int j = 0; j < length; j++) {
      uint64_t x = xorshift64();
      unsigned char ch = binary_data[x % 10000ull];
      printf("%d %llu %d\n", ch, x, x % 10000ull);
      sum += ch;
    }
    flag[i] = sum;
    if (sum >= 128) correct = 0;
    printf("%d\n", sum);
  }
  return correct;
}

ENC void temple(player* p) {
  say("You arrive to a huge temple.\n");
  say("There is a huge pile of gold before you - you come closer.\n");
  say("You notice a heavily ornamented old book: The Book of Flag. You open it.\n");

  say("It flashes and emits smoke - clearly some magic is involved.\n");
  say("Maybe it checks whether the owner's heart is pure and not cracked; that they didn't cheat in their adventure?\n");

  char flag[FLAGLEN+1] = {0};
  if (decrypt(flag)) {
    say("The book says: the flag is %s.\n", flag);
  }
  else {
    say("The book catches fire, and the knowledge within is lost forever...\n");
  }
}

uint64_t xorshift64() {
  uint64_t x = xstate;
  x ^= x << 7;
  x ^= x >> 9;
  return xstate = x;
}

ENC void end_of_encrypted() {}

int main() {
  printf("RogueTextAdventure binary is protected by x86perm-protector. Enter serial key:\n");
  unsigned int perm[256] = {0};
  char found[256] = {0};
  int sum = 0;
  for (int i = 0; i < 256; i++) {
    scanf("%x", &perm[i]);
    if (perm[i] >= 256) {
      printf("Error! Serial key invalid.\n");
      return 1;
    }
    found[perm[i]] = 1;
  }
  printf("Thank you for entering serial key.\n");
  for (int i = 0; i < 256; i++) {
    sum += found[i];
    printf("%02x ", perm[i]);
  }
  printf("\n");
  if (sum != 256) {
    printf("Error! Serial key invalid.\n");
    return 1;
  }

  volatile unsigned char* start = (volatile unsigned char*)entry;
  volatile unsigned char* end = (volatile unsigned char*)end_of_encrypted;
  mprotect((char*)start, end-start, PROT_READ | PROT_WRITE | PROT_EXEC);

  for (volatile unsigned char* ptr = start; ptr < end; ptr++) {
    *ptr = perm[*ptr];
  }

///  0000000000002000 <entry>:
//    2000:	55                   	push   rbp
 //   2001:	48 89 e5             	mov    rbp,rsp
   // 2004:	48 83 ec 30          	sub    rsp,0x30


  //temple(0);
  entry();
}
