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

namespace RNG {
namespace Good {
void init();
uint8_t get_u8();
} // namespace Good

namespace Bad {
void seed(uint32_t seed);
uint32_t get_u32();
uint16_t get_u16();
void add_to_seed(uint32_t mod);
} // namespace Bad
} // namespace RNG