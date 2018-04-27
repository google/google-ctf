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
#include <vector>
#include <string>
#include "NetSock.h"

#define MAP_W 640
#define MAP_H 480
#define MAP_SZ (MAP_W * MAP_H / 8)

#define TANK0_X (640-50)
#define TANK1_X (50)

const int WEAPON_EXPLOSION_RADIUS[4] = {
  -1, 10, 15, 50
};

const int WEAPON_EXPLOSION_DMG[4] = {
  -1, 18, 0, 8
};

struct Tank {
  // POD only.
  int x, y;  // Position of the core of the tank.
  int hp;    // Health.
};

struct Packet {
  std::string type;  // Use only 4-byte values.
  std::vector<uint8_t> data;
};

struct TargetingData {
  int weapon; // 1-3
  double power; // 10 - 100
  double angle; // 0 - 180
};

struct BulletEvent {
  int16_t x, y;  // Bullet position.
  int16_t weapon;  // If set, bullet explodes at this position
                    // with the given weapon effect.
};

// Returns false on disconnect.
bool SendPacket(NetSock *s, const Packet *p);

// Returns false on disconnect.
bool RecvPacket(NetSock *s, Packet *p);

bool SendText(NetSock *s, const char *t);
bool SendMap(NetSock *s, uint8_t *game_map);
bool SendTankData(NetSock *s, Tank tanks[2]);
bool SendTargetingData(NetSock *s, TargetingData *t);
bool SendBulletEvent(NetSock *s, const std::vector<BulletEvent>& bullet_ev);


