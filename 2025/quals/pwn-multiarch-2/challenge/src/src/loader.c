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

#include "loader.h"

#define MAGIC "MASM"
#define SEG_CODE 0x1
#define SEG_DATA 0x2
#define SEG_ARCH 0x3

bool load_segment(program_t* prog, size_t seg_hdr_offset, FILE* fp) {
    unsigned char segment_type;
    unsigned short segment_offset, segment_sz;

    if (fseek(fp, seg_hdr_offset, SEEK_SET) == -1) {
        ELOGERRNO("couldn't seek to segment header");
        return false;
    }

    if (fread(&segment_type, 1, 1, fp) != 1) {
        ELOGERRNO("couldn't read segment type");
        return false;
    }
    if (fread(&segment_offset, 2, 1, fp) != 1) {
        ELOGERRNO("couldn't read segment offset");
        return false;
    }
    if (fread(&segment_sz, 2, 1, fp) != 1) {
        ELOGERRNO("couldn't read segment size");
        return false;
    }

    if (fseek(fp, segment_offset, SEEK_SET) == -1) {
        ELOGERRNO("couldn't seek to segment chunk at %#x", segment_offset);
        return false;
    }

    void* data = malloc(segment_sz);
    if (fread(data, 1, segment_sz, fp) != segment_sz) {
        ELOGERRNO("couldn't read segment data");
        goto fail;
    }

    switch (segment_type) {
    case SEG_CODE:
        prog->code_bytes = data;
        prog->code_sz = segment_sz;
        break;
    case SEG_DATA:
        prog->data_bytes = data;
        prog->data_sz = segment_sz;
        break;
    case SEG_ARCH:
        prog->arch_bitmap = data;
        prog->arch_bitmap_sz = segment_sz;
        break;
    default:
        ELOG("invalid segment type: %d", segment_type);
        goto fail;
    }

    return true;

fail:
    free(data);
    return false;
}

program_t* load_program(const char* filepath) {
    program_t* prog = NULL;
    FILE* fp = fopen(filepath, "r");
    if (!fp) {
        ELOGERRNO("couldn't open file %s", filepath);
        return NULL;
    }

    char buf[0x10] = { 0 };
    if (fread(buf, 1, 4, fp) != 4) {
        ELOGERRNO("couldn't read magic");
        goto fail;
    }
    if (strncmp(buf, MAGIC, 4) != 0) {
        ELOG("bad magic");
        goto fail;
    }

    prog = calloc(1, sizeof(program_t));
    if (!load_segment(prog, 4, fp)) goto fail;
    if (!load_segment(prog, 9, fp)) goto fail;
    if (!load_segment(prog, 14, fp)) goto fail;

    return prog;

fail:
    if (prog) free_program(prog);
    if (fp) fclose(fp);
    return NULL;
}

void free_program(program_t* prog) {
    if (!prog) return;

    if (prog->code_bytes) {
        free(prog->code_bytes);
        prog->code_bytes = NULL;
    }
    if (prog->data_bytes) {
        free(prog->data_bytes);
        prog->data_bytes = NULL;
    }
    if (prog->arch_bitmap) {
        free(prog->arch_bitmap);
        prog->arch_bitmap = NULL;
    }
}