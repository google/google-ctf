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

__attribute((naked)) int write(int fd, const void *p, int n) {
  __asm__("li a7, 16; ecall; ret;");
}
void fake_respond(unsigned char *base_addr, char code) {
  base_addr = (unsigned char *)0x13370000;
  // status
  *(base_addr + 1) = code;  // STATUS_OK
  // control
  *base_addr = 0;
  // IRQ
  *(base_addr + 0xFFF) = 1;
}

#include "common.h"

__attribute((naked)) void main() {
  __asm__("lui sp, 0x8");
  char foo[512];
  foo[0] = '0';
  foo[1] = '\n';
  char *destination = (char *)0;
  volatile char *const cmd = (volatile char *)(0x13370000);
  typedef void (*fun)();
  fun f = 0;
  for (;;) {
    struct TransferHeader *tx_header = (struct TransferHeader *)(0x13370004);
    write(1, "W\n", 2);
    while (!((*cmd) & 128)) {
    }
    if (tx_header->acknowledged != 0x41) {
      write(1, "?\n", 2);
      fake_respond((unsigned char *)0x13370000, 4 /* error */);
      continue;
    }

    foo[0] = tx_header->index + '0';
    write(1, foo, 2);
    foo[0] = tx_header->end_index + '0';
    write(1, foo, 2);

    for (unsigned char i = 0; i < tx_header->size; i++)
      *destination++ = tx_header->data[i];

    tx_header->acknowledged = 1;
    fake_respond((unsigned char *)0x13370000, 1 /* status-ok */);

    if (tx_header->index == tx_header->end_index) break;
  }

  write(1, "Go\n", 3);
  // Jump to shellcode
  f();
}
