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



#ifndef INPUT_H
#define INPUT_H

#include "globals.h"
#include "player.h"

#define MAX_SPEED 4

void readInput() {
  if (arduboy.pressed(UP_BUTTON) && player.dirY > -MAX_SPEED) {
    player.dirY -= 1;
  }
  if (arduboy.pressed(DOWN_BUTTON) && player.dirY < MAX_SPEED) {
    player.dirY += 1;
  }
  if (arduboy.pressed(LEFT_BUTTON) && player.dirX > -MAX_SPEED) {
    player.dirX -= 1;
  }
  if (arduboy.pressed(RIGHT_BUTTON) && player.dirX < MAX_SPEED) {
    player.dirX += 1;
  }
}

#endif
