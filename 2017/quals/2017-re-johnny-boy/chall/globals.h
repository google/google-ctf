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



#ifndef GLOBALS_H
#define GLOBALS_H

#include <Arduboy2.h>
#include <ArduboyPlaytune.h>

#define STATE_INTRO 0
#define STATE_GAME_INIT 1
#define STATE_GAME_PLAYING 2
#define STATE_GAME_OVER 3
#define STATE_GAME_WIN 4

#define POINTS_TO_WIN 9999
#define GAME_DURATION 20

Arduboy2 arduboy;
ArduboyPlaytune tunes(arduboy.audio.enabled);

byte gameState = STATE_INTRO;

unsigned long score;

#endif
