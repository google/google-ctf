// Copyright 2021 Google LLC
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

#include <emulation/CPU/Z80.h>
#include "aes-mod.h"

#define ROM_SIZE 0x1000u
#define RAM_BASE 0x8000u
#define MEMORY_SIZE 0x10000u
#define RAM_REG_SIZE 256

/*
This value affects the difficulty of the challenge
18: leak after 1 round
12: leak after 2 rounds
10: leak after 3 rounds
8: leak after 4 rounds
*/
#define AES_ROUND_CYCLES 10

typedef struct {
    Z80 cpu;
    zboolean running;
    // 0x0000-0x7FFF: ROM
    // 0x8000-0xFFFF: RAM
    zuint8 memory[MEMORY_SIZE];

    // Hardware registers
    unsigned char tx_buf;
    unsigned char rx_buf;
    unsigned char io_ctrl;

    // Encryption peripheral
    struct AES_ctx aes_ctx;
    uint8_t aes_step;
    zusize aes_delay;
    uint8_t aes_key[AES_KEYLEN];
    uint8_t aes_block[AES_BLOCKLEN];
} emulator;

void emulator_init(emulator *emu, uint8_t *aes_key);
void emulator_aes_tick(emulator *emu, zusize delta_cycles);
