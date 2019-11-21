/******************************************************************************
 * Copyright 2018 Google
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *****************************************************************************/
#pragma once

#include <cstdint>

namespace Display {

/*
  /---A---\
  |       |
  F       B
  |       |
  +---G---+
  |       |
  E       C
  |       |
  \---D---/   [DP]
*/
static const uint8_t NUM_TO_SEG[10] = {
    // ABCDEFG.
    0b11111100,  // 0
    0b01100000,  // 1
    0b11011010,  // 2
    0b11110010,  // 3
    0b01100110,  // 4
    0b10110110,  // 5
    0b10111110,  // 6
    0b11100000,  // 7
    0b11111110,  // 8
    0b11110110,  // 9
};

const uint8_t Y = 0b01110110;
const uint8_t E = 0b10011110;
const uint8_t S = 0b10110110;

const uint8_t D = 0b11111100;
const uint8_t I = 0b01100000;
const uint8_t A = 0b11101110;
const uint8_t U = 0b01111100;

const uint8_t C = 0b10011100;
const uint8_t R = 0b11101110;

const uint8_t O = D;

void init();

void clear(bool auto_strobe=false);
void send_7seg(uint8_t value);
void send_single(bool b);
void clock();
void strobe();

}  // namespace Display
