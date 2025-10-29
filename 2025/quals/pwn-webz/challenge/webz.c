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


#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> 

#include "google-zlib/zlib.h"

#define MAX_INPUT_SIZE 4096
#define MAX_OUTPUT_SIZE (MAX_INPUT_SIZE * 2)

typedef struct EncodedWebz {
    uint8_t data[MAX_INPUT_SIZE];
    size_t size;
} EncodedWebz;

typedef struct DecodedWebz {
    uint8_t data[MAX_OUTPUT_SIZE];
    size_t size;
} DecodedWebz;

typedef struct WebzState {
    EncodedWebz encoded;
    DecodedWebz decoded;
    z_stream infstream;
    char ok_status[5];
} WebzState;

WebzState webz_state;

ssize_t check(ssize_t ret, const char * const msg) {
    if (ret == -1) {
        err(1, "%s", msg);
    }
    return ret;
}

ssize_t readn(int fd, void *buf, size_t n) {
    ssize_t nleft = n;
    ssize_t nread;
    char *ptr = buf;

    while (nleft > 0) {
        nread = check(read(fd, ptr, nleft), "readn");

        if (nread == 0) {
            break;
        }

        nleft -= nread;
        ptr += nread;
    }

    return (n - nleft);
}

void *webz_alloc(void *opaque, uint32_t items, uint32_t size) {
    (void)opaque;
    return calloc(items, size);
}

void webz_decompress(void) {
    size_t file_size = webz_state.encoded.size;
    uint8_t *file_data = webz_state.encoded.data;

    if (file_size < 12) {
        printf("Error: File too small to contain header.\n");
        return;
    }

    if (file_size > MAX_INPUT_SIZE) {
        printf("Error: File too large.\n");
        return;
    }

    // Magic Number from Header
    uint8_t* header = file_data;
    if (strncmp((char*)header, "WEBZ", 4) != 0) {
        printf("Error: Invalid magic number.\n");
        return;
    }

    // size
    uint16_t width = (header[4] << 8) | header[5];
    uint16_t height = (header[6] << 8) | header[7];

    if (width > 64 || height > 64) {
        printf("Error: Could not allocate memory for decompressed data.\n");
        return;
    }

    // Receipt
    memcpy(webz_state.ok_status, &header[8], 4);
    webz_state.ok_status[4] = '\0';

    // Remove header
    size_t compressed_size = file_size - 12;
    unsigned char* compressed_data = file_data + 12;

    webz_state.decoded.size = (unsigned long)width * height * 3;

    if (webz_state.decoded.size > MAX_OUTPUT_SIZE) {
        webz_state.decoded.size = MAX_OUTPUT_SIZE;
    }

    webz_state.infstream.avail_in = (uInt)compressed_size;
    webz_state.infstream.next_in = compressed_data;
    webz_state.infstream.avail_out = (uInt)webz_state.decoded.size;
    webz_state.infstream.next_out = webz_state.decoded.data;
    webz_state.infstream.zalloc = webz_alloc;
    webz_state.infstream.opaque = Z_NULL;

    int ret = inflateInit2(&webz_state.infstream, -15);
    webz_state.infstream.msg = webz_state.ok_status;

    if (ret != Z_OK) {
        printf("Error: inflateInit failed: %d\n", ret);
        return;
    }

    ret = inflate(&webz_state.infstream, Z_NO_FLUSH);

    if (ret != Z_STREAM_END) {
        printf("Error: inflate failed: %d\n", ret);
        inflateEnd(&webz_state.infstream);
        return;
    }

    inflateEnd(&webz_state.infstream);
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    while (1) {
        unsigned read_len = 0;

        readn(STDIN_FILENO, (char*)&read_len, sizeof(read_len));

        if (read_len == 0 || read_len > MAX_INPUT_SIZE) {
            puts("End.");
            break;
        }

        webz_state.encoded.size = readn(STDIN_FILENO, webz_state.encoded.data, read_len);
        webz_decompress();
        printf("Read receipt: %s\n", webz_state.infstream.msg);
    }
    return 0;
}
