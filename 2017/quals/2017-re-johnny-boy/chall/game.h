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



#ifndef GAME_H
#define GAME_H

#include "globals.h"
#include "inputs.h"
#include "player.h"

bool stateGamePlayingInit = false;

void stateGameInit() {
  newPlayer();
  newTargets();
  score = 0;
  gameState = STATE_GAME_PLAYING;
}

char scoreString[64];

void drawScore() {
  if (score >= POINTS_TO_WIN) {
    gameState = STATE_GAME_WIN;
  }

  unsigned long timePassed = (millis() - timeStart) / 1000;
  if (timePassed >= GAME_DURATION) {
    arduboy.setRGBled(0, 0, 0);
    gameState = STATE_GAME_OVER;
  }

  arduboy.setCursor(0, 0);
  sprintf(scoreString, "%d", score);
  arduboy.print(scoreString);
  arduboy.setCursor(115, 0);
  sprintf(scoreString, "%d", GAME_DURATION - timePassed);
  arduboy.print(scoreString);
}

void stateGamePlaying() {
  arduboy.clear();
  generateRandomtargets();
  drawScore();
  readInput();
  movePlayer();
  drawPlayer();
  drawTargets();
}

void stateGameOver() {
  arduboy.clear();
  arduboy.setCursor(3, 30);
  arduboy.print(F("Game Over! Try again!"));
  if (arduboy.justPressed(A_BUTTON | B_BUTTON)) {
    gameState = STATE_GAME_INIT;
  }
}

void stateGameWin() {
  arduboy.clear();
  arduboy.drawSlowXYBitmap(0, 0, WIN, 128, 64, 1);
}

#endif
