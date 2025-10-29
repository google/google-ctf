/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "emu.h"
#include "log.h"
#include "loader.h"

int main(int argc, char* argv[]) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc < 2) {
        ELOG("usage: %s [path to .masm file]", argv[0]);
        return 2;
    }

    ILOG("initializing multiarch emulator");

    program_t* prog = load_program(argv[1]);
    if (!prog) {
        ELOG("couldn't load multiarch program");
        return 1;
    }

    emulator_t* emu = new_emulator(prog);

    ILOG("executing program");
    while (execute_next_instruction(emu)) {
#if DEBUG
        dump_emulator_state(emu, true);
#endif  // DEBUG
    }
    if (emu->faulted) {
        ELOG("execution failed");
        dump_emulator_state(emu, true);
    }
    else {
        ILOG("done!");
    }

    free_emulator(emu);
    free_program(prog);
}