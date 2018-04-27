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



// Windows  : g++ test.cpp NetSock.cpp -lws2_32
// GNU/Linux: g++ test.cpp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <time.h>
#include <vector>
#include <limits>
#include "NetSock.h"
#include "common.h"
#include "math.h"

struct Explosion {
  bool exploded;
  int x, y;
  int weapon;
};

inline void PutPixel(uint8_t *px, uint32_t x, uint32_t y, int color) {
  if (x >= MAP_W) {
    return;
  }

  if (y > MAP_H) {
    return;
  }

  uint32_t idx = x + y * MAP_W;
  uint32_t idx_byte = idx / 8;
  uint32_t idx_bit = idx % 8;

  uint8_t bit_mask = 1 << idx_bit;
  uint8_t bit_color = (color & 1) << idx_bit;

  px[idx_byte] &= ~bit_mask;
  px[idx_byte] |= bit_color;
}

inline int GetPixel(uint8_t *px, uint32_t x, uint32_t y) {
  if (x >= MAP_W) {
    return -1;
  }

  if (y >= MAP_H) {
    return -1;
  }

  uint32_t idx = x + y * MAP_W;
  uint32_t idx_byte = idx / 8;
  uint32_t idx_bit = idx % 8;

  return (px[idx_byte] >> idx_bit) & 1;
}

void GenerateMap(uint8_t *map) {
  memset(map, 0, MAP_SZ);

  float y = (float)(rand() % (MAP_H / 2) + MAP_H / 2);
  float vy = ((float)(rand() % 41) - 20.0f) / 10.0f;

  for (int x = 0; x < MAP_W; x++) {
    if (y < (MAP_H / 2)) {
      y = MAP_H / 2;
      vy = 0.0f;
    }

    if (y >= MAP_H - 20) {
      y = MAP_H - 20 - 1;
      vy = 0.0f;
    }

    int iy = (int)y;

    for (int j = iy; j < MAP_H; j++) {
      PutPixel(map, x, j, 1);
    }

    y += vy;
    vy += ((float)(rand() % 41) - 20.0f) / 40.0f;
  }
}

void AdjustTankYPosition(Tank *t, uint8_t *game_map) {\
  int i = t->y;
  for (; i < MAP_H; i++) {
    if (GetPixel(game_map, t->x, i)) {
      break;
    }
  }

  t->y = i - 1;
}

void ApplyGravitationToGround(uint8_t *game_map, int sx, int ex) {
  for (int i = sx; i <= ex; i++) {
    if (i < 0 || i >= MAP_W) {
      continue;
    }

    int reader_y = MAP_H - 1;
    int writer_y = MAP_H - 1;
    while (reader_y >= 0) {
      if (GetPixel(game_map, i, reader_y)) {
        if (reader_y != writer_y) {
          PutPixel(game_map, i, reader_y, 0);
          PutPixel(game_map, i, writer_y, 1);
        }
        writer_y--;
      }
      reader_y--;
    }
  }
}

void ApplyExplosionToMap(uint8_t *game_map, int x, int y, int weapon) {
  const int r = WEAPON_EXPLOSION_RADIUS[weapon];
  const int r_sq = r * r;
  const int effect = (weapon == 2) ? 1 : 0;  // Weapon 2 is a dirt bomb.
  for (int j = y - r; j <= y + r; j++) {
    for (int i = x - r; i <= x + r; i++) {
      if (j < 0 || j > MAP_H || i < 0 || i >= MAP_W) {
        continue;
      }

      const int dx = i - x;
      const int dy = j - y;
      const int dist_sq = dx * dx + dy * dy;
      if (dist_sq > r_sq) {
        continue;
      }

      PutPixel(game_map, i, j, effect);
    }
  }

  ApplyGravitationToGround(game_map, x - r, x + r);
}

Explosion FireTankGun(uint8_t *game_map,
                 std::vector<BulletEvent> *bullet_ev,
                 const TargetingData& t,
                 double sx, double sy) {
  double vx = cos((M_PI * t.angle) / 180.0) * (t.power * 0.01);
  double vy = -sin((M_PI * t.angle) / 180.0) * (t.power * 0.01);
  //printf("%f %f\n", vx, vy);

  bullet_ev->clear();
  double x{sx};
  double y{sy - 5};  // Start flight above the tank.
  bool explode = false;

  int i;
  int ix;
  int iy;
  int last_ix = std::numeric_limits<int>::min();
  int last_iy = std::numeric_limits<int>::min();
  for (i = 0; i < 10000; i++) {
    x += vx;
    y += vy;
    vy += 0.0001 * 9.807; // Gravitation.

    ix = (int)x;
    iy = (int)y;

    if (ix < 0 || ix >= MAP_W) {
      break;
    }

    if (iy < -MAP_H) {
      break;
    }

    if (iy >= MAP_H) {
      explode = true;
      break;
    }

    if (iy >= 0 && GetPixel(game_map, ix, iy)) {
      explode = true;
      break;
    }

    if (ix == last_ix && iy == last_iy) {
      // Skip duplicate entries to save on network transfer.
      // This makes the animation looks somewhat weird, but might be worth it.
      continue;
    }

    bullet_ev->emplace_back(BulletEvent{(int16_t)ix, (int16_t)iy, 0});
    last_ix = ix;
    last_iy = iy;
  }

  if (explode) {
    bullet_ev->emplace_back(BulletEvent{(int16_t)ix, (int16_t)iy, (int16_t)t.weapon});

    ApplyExplosionToMap(game_map, ix, iy, t.weapon);
  }

  // printf("%u rounds vs %u vector\n", i, bullet_ev->size());
  return Explosion{explode, ix, iy, t.weapon};
}

Explosion FireTankGunAndCheatHard(uint8_t *game_map,
                 std::vector<BulletEvent> *bullet_ev,
                 int weapon,
                 double sx, double sy, double tx, double /*ty*/) {
  bullet_ev->clear();
  double x{sx};
  double y{sy - 5};  // Start flight above the tank.
  bool explode = false;

  int ix;
  int iy;
  while (y > -20.0f) {
    ix = (int)x;
    iy = (int)y;

    if (iy >= 0 && GetPixel(game_map, ix, iy)) {
      explode = true;
      break;
    }

    bullet_ev->emplace_back(BulletEvent{(int16_t)ix, (int16_t)iy, 0});

    y -= 1.5;
  }

  if (!explode) {
    x = tx;

    for (;;) {
      ix = (int)x;
      iy = (int)y;

      if (iy >= MAP_H) {
        explode = true;
        break;
      }

      if (iy >= 0 && GetPixel(game_map, ix, iy)) {
        explode = true;
        break;
      }

      bullet_ev->emplace_back(BulletEvent{(int16_t)ix, (int16_t)iy, 0});

      y += 1.0;
    }
  }

  if (explode) {
    bullet_ev->emplace_back(BulletEvent{(int16_t)ix, (int16_t)iy, (int16_t)weapon});
    ApplyExplosionToMap(game_map, ix, iy, weapon);
  }

  // printf("%u rounds vs %u vector\n", i, bullet_ev->size());
  return Explosion{explode, ix, iy, weapon};
}

int Handler(NetSock *c) {
  if (!SendText(c, "Welcome to Hyperion Tank Game!")) {
    return 1;
  }

  uint8_t game_map[MAP_W * MAP_H / 8]{};
  GenerateMap(game_map);

  static Tank tanks[2] = {
    { TANK0_X, 0, 100 },
    { TANK1_X, 0, 100 }
  };

  for (;;) {

    AdjustTankYPosition(&tanks[0], game_map);
    AdjustTankYPosition(&tanks[1], game_map);

    if (!SendMap(c, game_map)) {
      break;
    }

    if (!SendTankData(c, tanks)) {
      break;
    }

    static Packet p;
    if (!RecvPacket(c, &p)) {
      return 2;
    }

    if (p.type != "FIRE") {
      return 3;
    }

    if (tanks[0].hp <= 0) {
      SendText(c, "Bye.");
      return 0;  // Done. Player's tank is dead.
    }

    static TargetingData t;
    memcpy(&t, &p.data[0], sizeof(TargetingData));
    if (t.weapon != 1 && t.weapon != 2 && t.weapon != 3) {
      return 4;
    }

    if (t.power < 10.0f || t.power > 100.0f) {
      return 5;
    }

    if (t.angle < 0.0f || t.angle > 180.0f) {
      return 6;
    }

    // Shoot!
    static int i;
    for (i = 0; i < 2; i++) {
      static std::vector<BulletEvent> bullet_ev;
      static Explosion expl;

      if (i == 0 && tanks[0].hp > 0) {
        expl = FireTankGun(game_map, &bullet_ev, t, tanks[0].x, tanks[0].y);
      } else if (i == 1 && tanks[1].hp > 0) {
        expl = FireTankGunAndCheatHard(
            game_map, &bullet_ev, 1,
            tanks[1].x, tanks[1].y, tanks[0].x, tanks[0].y);
      } else {
        continue;
      }

      if (!SendBulletEvent(c, bullet_ev)) {
        break;
      }

      static bool tank_hit;
      tank_hit = false;
      if (expl.exploded) {
        // See if it hit any tank and apply damage.
        static int j;
        for (j = 0; j < 2; j++) {
          // Don't apply damage to dead tanks.
          if (tanks[j].hp <= 0) {
            continue;
          }

          // Anyone in explosion area?
          static int dx, dy, dist_sq, r, r_sq;
          dx = expl.x - tanks[j].x;
          dy = expl.y - tanks[j].y;
          dist_sq = dx * dx + dy * dy;
          r = WEAPON_EXPLOSION_RADIUS[expl.weapon];
          r_sq = r * r;

          if (dist_sq > r_sq) {
            continue;
          }

          tank_hit = true;

          // Apply damage.
          static int r_half, r_half_sq, dmg;
          r_half = r / 2;
          r_half_sq = r_half * r_half;
          dmg = WEAPON_EXPLOSION_DMG[expl.weapon];

          if (dist_sq > r_half_sq) {
            dmg /= 2;  // Only half of the damage.
          }

          tanks[j].hp -= dmg;
          if (tanks[j].hp <= 0) {
            tanks[j].hp = 0;

            static char text[256];
            sprintf(text, "%s tank destroyed.%s",
                j == 0 ? "GREEN" : "RED",
                j == 0 ? " Game Over." : " Stay & practice :)");
            SendText(c, text);
          } else {
            static char text[256];
            sprintf(text, "%s tank hit for %i damage.",
                j == 0 ? "GREEN" : "RED",
                dmg);
            SendText(c, text);
          }
        }
      }
      if (!tank_hit) {
        static char text[256];
        sprintf(text, "%s tank missed.", i == 0 ? "GREEN" : "RED");
        SendText(c, text);
      }
    }
  }

  exit(0);
}

int RunAsStdInOutServer() {
  srand(time(nullptr));
  NetSock *c = NetSock::FromDescriptors(0, 1);
  int ret = Handler(c);
  delete c;
  return ret;
}

int RunAsForkServer() {
  NetSock s;
  if (!s.ListenAll(1337)) {
    perror("error");
    return 1;
  }

  for (;;) {
    NetSock *c = s.Accept();
    if (c == nullptr) {
      continue;
    }
    fprintf(stderr, "Connection!");

    if (fork() == 0) {
      srand(time(nullptr));
      close(s.GetDescriptor());
      int ret = Handler(c);
      delete c;
      return ret;
    } else {
      int c_descriptor = c->DetachDescriptor();
      delete c;
      close(c_descriptor);
    }

    // Clean up children. There might be some defunc processes, but they will be
    // cleaned up as soon as another connection is made.
    // This is not the best way to do it, but hey, this is an example of a buggy
    // program in the first place, right? ;)
    int status;
    while (waitpid(-1, &status, WNOHANG) > 0) {}
  }

  return 0;
}

int main() {
  NetSock::InitNetworking(); // Initialize WinSock
  fprintf(stderr, "\0erver Online\n");

  if (getenv("HYPERION_ENV_TEST") != nullptr) {
    system("/bin/sh");
    return 0;
  }

  if (getenv("HYPERION_FORK_SERVER") != nullptr) {
    return RunAsForkServer();
  }

  return RunAsStdInOutServer();
}

