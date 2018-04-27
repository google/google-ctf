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



#ifndef PLAYER_H
#define PLAYER_H

#include <Arduino.h>
#include "globals.h"

#define PLAYER_SIZE 6
#define TARGET_SIZE 2
#define MAX_TARGETS 4

const byte coinScore[] PROGMEM = {
  0x90,88, 0,75, 0x80, 0x90,91, 0,180, 0x80, 0xf0};

struct Player {
 public:
  int x;
  int y;
  int dirX;
  int dirY;
};

struct Target {
 public:
  int x;
  int y;
  bool active;
};

Player player;
Target targets[MAX_TARGETS];
unsigned long timeStart;

void newPlayer() {
  player.x = WIDTH / 2 - PLAYER_SIZE / 2;
  player.y = HEIGHT / 2 - PLAYER_SIZE / 2;
  player.dirX = 0;
  player.dirY = 0;

  timeStart = millis();
}

void newTargets() {
  for (int i=0; i<MAX_TARGETS; i++) {
    targets[i].active = false;
  }
}

void drawPlayer() {
  arduboy.drawCircle(player.x, player.y, PLAYER_SIZE / 2, 1);
}

void drawTargets() {
  for (int i=0; i<MAX_TARGETS; i++) {
    if (!targets[i].active) {
      continue;
    }
    arduboy.drawCircle(targets[i].x, targets[i].y, TARGET_SIZE / 2, 1);
  }
}

void checkHitWalls() {
  if (player.x > WIDTH - PLAYER_SIZE / 2) {
    player.x = WIDTH - (PLAYER_SIZE / 2 + 1);
    player.dirX = -player.dirX;
  }
  if (player.x < PLAYER_SIZE / 2) {
    player.x = PLAYER_SIZE / 2 + 1;
    player.dirX = -player.dirX;
  }
  if (player.y < PLAYER_SIZE / 2) {
    player.y = PLAYER_SIZE / 2 + 1;
    player.dirY = -player.dirY;
  }
  if (player.y > HEIGHT - PLAYER_SIZE / 2) {
    player.y = HEIGHT - (PLAYER_SIZE / 2 + 1);
    player.dirY = -player.dirY;
  }
}

void generateRandomtargets() {
  if (random(0, 25) != 24) {
    return;
  }
  for (int i=0; i<MAX_TARGETS; i++) {
    if (targets[i].active) {
      continue;
    }
    targets[i].active = true;
    targets[i].x = random(TARGET_SIZE / 2, WIDTH - TARGET_SIZE / 2);
    targets[i].y = random(TARGET_SIZE / 2, HEIGHT - TARGET_SIZE / 2);
    break;
  }
}

void checkHitTarget() {
  for (int i=0; i<MAX_TARGETS; i++) {
    if (!targets[i].active) {
      continue;
    }
    if (player.x - PLAYER_SIZE / 2 <= targets[i].x + TARGET_SIZE / 2 &&
        player.x + PLAYER_SIZE / 2 >= targets[i].x - TARGET_SIZE / 2 &&
        player.y - PLAYER_SIZE / 2 <= targets[i].y + TARGET_SIZE / 2 &&
        player.y + PLAYER_SIZE / 2 >= targets[i].y - TARGET_SIZE / 2) {
      targets[i].active = false;
      score += 1;
      long color = random(1, 9);
      arduboy.setRGBled(((color >> 2) & 1) * 255,
                        ((color >> 1) & 1) * 255,
                        (color & 1) * 255);
      tunes.playScore(coinScore);
    }
  }
}

void movePlayer() {
  player.x += player.dirX;
  player.y += player.dirY;
  checkHitWalls();
  checkHitTarget();
}

#endif
