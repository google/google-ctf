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



#ifndef MENU_H
#define MENU_H

#include "globals.h"

void stateIntro() {
  float resize1 = abs(cos(millis()/ 1000.0));
  float resize2 = abs(sin(millis()/ 1000.0));
  arduboy.drawSlowXYBitmap(0, 0, LOGO, 128, 31, 1);
  arduboy.setCursor(23, 40);
  arduboy.print(F("Press a button"));
  arduboy.setCursor(38, 50);
  arduboy.print(F("to start!"));
  if (arduboy.justPressed(A_BUTTON | B_BUTTON)) {
    gameState = STATE_GAME_INIT;
  }
}

#endif
