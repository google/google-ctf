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

#include <stdio.h>
#include <string.h>

#include "emulation.h"
#include "debug.h"


#define IO_CTRL_TX 0
#define IO_CTRL_RX 1

zuint8 emulator_in(void *context, zuint16 port) {
    emulator *emu = context;
    zuint8 in_port = port & 0xFF;

    switch(in_port) {
        case 0: { //IoData
            debug_print("IN IO_DATA (0) , read, value: %02hhx\n", emu->rx_buf);
            return emu->rx_buf;
        }
            break;
        case 1: // IoCtrl
            debug_print("IN IO_CTRL (1), read, value: %02hhx\n", emu->io_ctrl);
            return emu->io_ctrl;
            break;

        // AES out buffer
        case 0x20:
        case 0x21:
        case 0x22:
        case 0x23:
        case 0x24:
        case 0x25:
        case 0x26:
        case 0x27:
        case 0x28:
        case 0x29:
        case 0x2A:
        case 0x2B:
        case 0x2C:
        case 0x2D:
        case 0x2E:
        case 0x2F:
            debug_print("IN AES_IN (%#02hhx), read, value: %02hhx\n", in_port, emu->memory[RAM_BASE + in_port]);
            return emu->memory[RAM_BASE + in_port];
            break;

        case 0x30:
            debug_print("IN AES_CTRL (0x30), read, value: %02hhx\n", (uint8_t)(emu->aes_step > 0));
            return emu->aes_step > 0;
            break;

        default:
            debug_print("IN [UNK], port: %02hhx\n", in_port);
            break;
    }
    return 0;
}


void emulator_out(void *context, zuint16 port, zuint8 value) {
    emulator *emu = context;
    zuint8 out_port = port & 0xFF;
    switch(out_port) {
        case 0: //IoData
            debug_print("OUT 0, print, value: %02hhx\n", value);
            emu->tx_buf = value;
            break;
        case 1: //IoCtrl
            debug_print("OUT 1, print, value: %02hhx\n", value);
            emu->io_ctrl = value;

            if((emu->io_ctrl>>IO_CTRL_RX) & 1) {
                int c = getc(stdin);
                if(c != EOF) {
                    emu->rx_buf = (unsigned char)c;
                    emu->io_ctrl &= ~(1<<IO_CTRL_RX);
                }
            }

            if((emu->io_ctrl>>IO_CTRL_TX) & 1) {
                putc(emu->tx_buf, stdout);
                emu->io_ctrl &= ~(1<<IO_CTRL_TX);
            }
            break;

        // AES in buffer
        case 0x10:
        case 0x11:
        case 0x12:
        case 0x13:
        case 0x14:
        case 0x15:
        case 0x16:
        case 0x17:
        case 0x18:
        case 0x19:
        case 0x1A:
        case 0x1B:
        case 0x1C:
        case 0x1D:
        case 0x1E:
        case 0x1F:
            debug_print("OUT AES_IN (%#02hhx), read, value: %02hhx\n", out_port, value);
            emu->memory[RAM_BASE + out_port] = value;
            break;

        // AES ctrl port
        case 0x30:
            debug_print("OUT AES_CTRL (0x30), value: %02hhx\n", value);
            if(value & 1) {
                debug_print("Begin AES encryption\n");

                AES_init_ctx(&emu->aes_ctx, emu->aes_key);
                memcpy(&emu->memory[RAM_BASE + 0x20], emu->aes_block, AES_BLOCKLEN);
                memcpy(emu->aes_block, &emu->memory[RAM_BASE + 0x10], AES_BLOCKLEN);

                debug_print("AES data: ");
                for(size_t i = 0; i < AES_BLOCKLEN; i++) {
                    debug_print("%02x", emu->aes_block[i]);
                }
                debug_print("\n");
                debug_print("AES key: ");
                for(size_t i = 0; i < AES_KEYLEN; i++) {
                    debug_print("%02x", emu->aes_key[i]);
                }
                debug_print("\n");
                emu->aes_step = 1;
            } else {
                emu->aes_step = 0;
                emu->aes_delay = 0;
            }
            break;

        default:
            debug_print("OUT [UNK], port: %02hhx, value: %02hhx\n", out_port, value);
            break;
    }
    return;
}


zuint8 emulator_read(void *context, zuint16 address) {
    emulator *emu = context;
    debug_print("Read: %04hx, %02hhx\n", address, emu->memory[address]);
    if(address >= RAM_BASE && address < RAM_BASE+RAM_REG_SIZE) {
        return emulator_in(context, address & 0xFF);
    } else {
        return emu->memory[address];
    }
}


void emulator_write(void *context, zuint16 address, zuint8 value) {
    emulator *emu = context;
    debug_print("Write: %04hx, %02hhx\n", address, value);
    if(address >= RAM_BASE /*&& address < MEMORY_SIZE*/) {
        if(address < RAM_BASE + RAM_REG_SIZE) {
            emulator_out(context, address, value);
        } else {
            emu->memory[address] = value;
        }
    }
    return;
}

zuint32 emulator_int_data(void *context) {
    return 0;
}


void emulator_halt(void *context, zboolean state) {
    emulator *emu = context;
    if(state) {
        emu->running = FALSE;
    }
    debug_print("Halt: %d\n", state);
    return;
}


void emulator_aes_tick(emulator *emu, zusize delta_cycles) {
    if(emu->aes_step == 0) {
        return;
    }

    delta_cycles += emu->aes_delay;
    emu->aes_delay = 0;

    while(delta_cycles >= AES_ROUND_CYCLES) {
        delta_cycles -= AES_ROUND_CYCLES;
        int8_t res = AES_ECB_encrypt_step(&emu->aes_ctx, emu->aes_block, emu->aes_step++);
        if(res < 0) {
            debug_print("ERROR: Inconsistent AES state\n");
            memset(emu->aes_block, 0, AES_BLOCKLEN);
            emu->aes_step = 0;
            emu->aes_delay = 0;
        } else if(res == 1) {
            emu->aes_step = 0;
            emu->aes_delay = 0;
            debug_print("Performed last AES step\n");
            debug_print("AES data: ");
            for(size_t i = 0; i < AES_BLOCKLEN; i++) {
                debug_print("%02x", emu->aes_block[i]);
            }
            debug_print("\n");
            memcpy(&emu->memory[RAM_BASE + 0x20], emu->aes_block, AES_BLOCKLEN);
            break;
        } else {
            debug_print("Performed AES step %d\n", emu->aes_step-1);
            debug_print("AES data: ");
            for(size_t i = 0; i < AES_BLOCKLEN; i++) {
                debug_print("%02x", emu->aes_block[i]);
            }
            debug_print("\n");
        }
    }

    if(emu->aes_step > 0) {
        emu->aes_delay = delta_cycles;
    }
}

void emulator_init(emulator *emu, uint8_t *aes_key) {
    emu->cpu.context = emu;
    emu->running = TRUE;

    emu->cpu.in = emulator_in;
    emu->cpu.read = emulator_read;
    emu->cpu.write = emulator_write;
    emu->cpu.int_data = emulator_int_data;
    emu->cpu.halt = emulator_halt;
    emu->cpu.out = emulator_out;

    emu->rx_buf = 0;
    emu->tx_buf = 0;
    emu->io_ctrl = 0;
    emu->aes_step = 0;
    emu->aes_delay = 0;

    memset(emu->memory, 0, MEMORY_SIZE);
    memset(emu->aes_block, 0, AES_BLOCKLEN);
    memcpy(emu->aes_key, aes_key, AES_KEYLEN);
}
