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
#include <avr/io.h>

// Port B
namespace PortB {
constexpr uint8_t CS_DSPL = 1 << PB0;
constexpr uint8_t DSPL_RESET = 1 << PB1;
constexpr uint8_t RS = 1 << PB2;
constexpr uint8_t SS = 1 << PB2;
constexpr uint8_t MOSI = 1 << PB3;
constexpr uint8_t MISO = 1 << PB4;
constexpr uint8_t SCK = 1 << PB5;
constexpr uint8_t BTN_0 = 1 << PB6;
constexpr uint8_t BTN_1 = 1 << PB7;
} // namespace PortB

// Port C
namespace PortC {
constexpr uint8_t CS_F = 1 << PC0;
constexpr uint8_t BTN_2 = 1 << PC1;
constexpr uint8_t BTN_3 = 1 << PC2;
constexpr uint8_t CS_CARD = 1 << PC3;
constexpr uint8_t I2C_DATA = 1 << PC4;
constexpr uint8_t I2C_CLK = 1 << PC5;
constexpr uint8_t BTN_4 = 1 << PC7;
} // namespace PortC

// Port D
namespace PortD {
constexpr uint8_t BTN_5 = 1 << PD0;
constexpr uint8_t BTN_6 = 1 << PD1;
constexpr uint8_t BTN_7 = 1 << PD2;
constexpr uint8_t BTN_8 = 1 << PD3;
constexpr uint8_t BTN_9 = 1 << PD4;
constexpr uint8_t BTN_10 = 1 << PD5;
constexpr uint8_t BTN_11 = 1 << PD7;
constexpr uint8_t EXTENSION_1 = 1 << PD6;
constexpr uint8_t EXTENSION_2 = 1 << PD7;
} // namespace PortD
