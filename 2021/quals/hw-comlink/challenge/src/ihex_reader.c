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

#include <string.h>
#include "debug.h"
#include "ihex_reader.h"

static void* read_target = NULL;
size_t target_size;
ihex_bool_t read_success;


ihex_bool_t ihex_data_read (struct ihex_state *ihex, ihex_record_type_t type, ihex_bool_t checksum_error) {
    if(read_target == NULL) {
        fprintf(stderr, "ERROR: Read target not set\n");
        return 0;
    }

    if(checksum_error) {
        fprintf(stderr, "ERROR: Checksum error in iHex file, aborting\n");
        read_success = 0;
        return 0;
    }

    if (type == IHEX_DATA_RECORD) {
        unsigned long address = (unsigned long) IHEX_LINEAR_ADDRESS(ihex);
        if(address + ihex->length > target_size) {
            fprintf(stderr, "ERROR: Writing out of bounds\n");
            return 0;
        }

        debug_print("Writing %hhu bytes starting at address %lu, data: ", ihex->length, address);
        for(size_t i = 0; i < ihex->length; i++) {
            debug_print("%02x", ihex->data[i]);
        }
        debug_print("\n");
        memcpy((unsigned char*)read_target + address, ihex->data, ihex->length);
    } else if (type == IHEX_END_OF_FILE_RECORD) {
        read_target = NULL;
        target_size = 0;
        read_success = 1;
        debug_print("Done reading ihex file\n");
    }
    return 1;
}

void set_ihex_read_target(void* memory, size_t len) {
    read_target = memory;
    target_size = len;
}

ihex_bool_t get_ihex_read_result(void) {
    return read_success;
}
