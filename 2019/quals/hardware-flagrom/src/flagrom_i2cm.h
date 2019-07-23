// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once
// I2C-M module.

#include "emu8051/emu8051.h"

bool sfr_i2c_module(
    emu8051 *emu,
    emu8051::access_type_t access_type,
    emu8051::address_type_t addr_type, uint8_t addr,
    uint8_t *value);
