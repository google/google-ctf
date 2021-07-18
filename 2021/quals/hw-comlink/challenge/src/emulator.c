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

#include "ihex_reader.h"
#include "debug.h"
#include "emulation.h"

#define IHEX_MAX_SIZE 0x10000u
#define MAX_MAX_CYCLES 0x100000lu

//uint8_t aes_key[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }; // Test key
uint8_t aes_key[] = { 0x1d, 0x5, 0xef, 0xe8, 0x63, 0xc3, 0xd9, 0x92, 0xa8, 0xf1, 0x7b, 0xce, 0x93, 0x47, 0x59, 0x5b };

uint8_t emulator_load_rom(emulator *emu, char *path) {
    FILE *f = fopen(path, "rb");
    if(f == NULL) {
        fprintf(stderr, "ERROR: Failed to open firmware, aborting.\n");
        return 0;
    }
    if(fseek(f, 0, SEEK_END)) {
        fprintf(stderr, "ERROR: Failed to determine firmware size, aborting.\n");
        return 0;
    }
    long ihex_length = ftell(f);
    if(ihex_length == -1) {
        fprintf(stderr, "ERROR: Failed to determine firmware size, aborting.\n");
        return 0;
    }
    if(fseek(f, 0, SEEK_SET)) {
        fprintf(stderr, "ERROR: Failed to start reading firmware, aborting.\n");
        return 0;
    }
    if(ihex_length > IHEX_MAX_SIZE) {
        fprintf(stderr, "ERROR: Firmware file too large, aborting.\n");
        return 0;
    }

    debug_print("Allocating %ld bytes of memory for firwmare.\n", ihex_length);
    char *ihex_data = malloc(ihex_length);
    size_t num_read = fread(ihex_data, ihex_length, 1, f);
    fclose(f);
    if(num_read != 1) {
        fprintf(stderr, "ERROR: Failed to read firmware file, aborting.\n");
        return 0;
    }

    struct ihex_state ihex;
    set_ihex_read_target(emu->memory, ROM_SIZE);
    ihex_begin_read(&ihex);
    ihex_read_bytes(&ihex, ihex_data, ihex_length);
    ihex_end_read(&ihex);

    free(ihex_data);

    if(!get_ihex_read_result()) {
        fprintf(stderr, "ERROR: Failed to parse Intel Hex format, aborting.\n");
        return 0;
    }

    return 1;
}


int run_emulator(char *rom_path, zusize max_cycles) {
    // Setup
    emulator emu;

    emulator_init(&emu, aes_key);
    if(!emulator_load_rom(&emu, rom_path)) {
        return -1;
    }

    // Startup
    z80_power(&emu.cpu, TRUE);
    z80_reset(&emu.cpu);
    zusize cycles;
    zusize total_cycles = 0;

    // Run emulator
    while(emu.running) {
        cycles = z80_run(&emu.cpu, 1);
        total_cycles += cycles;
        debug_print("Ran %lu cycles, total: %lu\n", cycles, total_cycles);

        emulator_aes_tick(&emu, cycles);

        if(total_cycles >= max_cycles) {
            fprintf(stderr, "ERROR: Max number of cycles hit, exiting.\n");
            return -1;
        }
    }

    fflush(stdout);

    return 0;
}


int main(int argc, char **argv, char **envp) {
    if(argc < 3) {
        fprintf(stderr, "Usage: %s <firmware.ihx> <max cycles>\n", argv[0]);
        return 1;
    }

    zusize max_cycles = strtoul(argv[2], NULL, 10);
    if(max_cycles == 0 || max_cycles > MAX_MAX_CYCLES) {
        fprintf(stderr, "ERROR: Invalid max cycles \"%s\", must be 1-%lu exiting.\n", argv[2], MAX_MAX_CYCLES);
        return -1;
    }

    return run_emulator(argv[1], max_cycles);
}
