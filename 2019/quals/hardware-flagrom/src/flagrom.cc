// Copyright 2019 Google LLC
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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <openssl/md5.h>
#include <seeprom.h>

#include <string>
#include <vector>

#include "emu8051/emu8051.h"
#include "flagrom.h"
#include "flagrom_i2cm.h"

static const char *kProofOfWorkPrefix = "flagrom-";
static const int kProofOfWorkDifficulty = 3;

static uint8_t firmware[0x10000];
static uint8_t usercode[0x10000];
static char flag[128];  // Temporary flag buffer.

static bool done_marker;

struct seeprom *dev_i2c;

bool sfr_done_marker(
    emu8051 */*emu*/,
    emu8051::access_type_t access_type,
    emu8051::address_type_t /*addr_type*/, uint8_t /*addr*/,
    uint8_t *value) {
  if (access_type == emu8051::access_type_t::READ) {
    *value = 0;
    return true;
  }

  done_marker = (bool)*value;
  return true;
}

bool sfr_debug_print(
    emu8051 *emu,
    emu8051::access_type_t access_type,
    emu8051::address_type_t /*addr_type*/, uint8_t /*addr*/,
    uint8_t *value) {
  // At any type of access print all the register states.
  printf("--- DEBUG DUMP:               pc: %.4x\n"
         " a: %.2x     b: %.2x   psw: %.2x  dptr: %.4x    \n",
         emu->pc_get(),
         emu->a_get(), emu->b_get(), emu->psw_get(), emu->dptr_get());
  for (int i = 0; i < 8; i++) {
    printf("r%i: %.2x    ", i, emu->r_get(i));
    if (i == 3 || i == 7) {
      putchar('\n');
    }
  }

  // The read value can be whatever.
  if (access_type == emu8051::access_type_t::READ) {
    *value = 0;
  }

  return true;
}

bool sfr_character_output(
    emu8051 */*emu*/,
    emu8051::access_type_t access_type,
    emu8051::address_type_t /*addr_type*/, uint8_t /*addr*/,
    uint8_t *value) {
  static uint8_t output_counter;

  // On read return the number of output characters (8-bit).
  if (access_type == emu8051::access_type_t::READ) {
    *value = output_counter;
    return true;
  }

  // On write output the written character to stdout.
  putchar(*value);
  output_counter++;

  return true;
}

bool sfr_gpio_module(
    emu8051 */*emu*/,
    emu8051::access_type_t access_type,
    emu8051::address_type_t /*addr_type*/, uint8_t addr,
    uint8_t *value) {
  if (addr == 0xfa) {  // SCL
    if (access_type == emu8051::access_type_t::WRITE) {
      seeprom_write_scl(dev_i2c, (bool)(*value & 1));
    } else {
      *value = 0xff;  // Can't read from SCL.
    }
  }

  if (addr == 0xfb) {  // SDA
    if (access_type == emu8051::access_type_t::WRITE) {
      seeprom_write_sda(dev_i2c, (bool)(*value & 1));
    } else {
      *value = seeprom_read_sda(dev_i2c);
    }
  }

  return true;
}

void read_firmware() {
  FILE *f = fopen("firmware.8051", "rb");
  if (f == nullptr) {
    fprintf(stderr, "error: firmware.8051 is missing\n");
    exit(1);
  }

  fread(firmware, 1, sizeof(firmware), f);
  fclose(f);
}

void read_flag() {
  FILE *f = fopen("flag.txt", "rb");
  if (f == nullptr) {
    strcpy(flag, "On the real server the flag is loaded here.");
  } else {
    fread(flag, 1, sizeof(flag), f);
    fclose(f);
  }
}

void read_proof_of_work() {
  FILE *f = fopen("/dev/urandom", "rb");
  if (f == nullptr) {
    fprintf(stderr, "error: could not open /dev/urandom\n");
    exit(1);
  }

  uint8_t prefix[kProofOfWorkDifficulty];
  if (fread(&prefix, 1, sizeof(prefix), f) != sizeof(prefix)) {
    fprintf(stderr, "error: could not read prefix\n");
    exit(1);
  }
  fclose(f);

  printf("What's a printable string less than 64 bytes that starts ");
  printf("with %s whose md5 starts with ", kProofOfWorkPrefix);
  for (int i = 0; i < kProofOfWorkDifficulty; i++) {
    printf("%.2x", prefix[i]);
  }
  printf("?\n");

  char response[64];
  if (fgets(response, sizeof(response), stdin) == nullptr) {
    puts("Didn't quite hear that. Good bye.");
    exit(1);
  }
  response[strlen(response) - 1] = '\0';

  for (unsigned int i = 0; i < strlen(response); i++) {
    if (!isprint(response[i])) {
      puts("That's not isprint()able! Good bye.");
      exit(1);
    }
  }

  if (strncmp(response, kProofOfWorkPrefix, strlen(kProofOfWorkPrefix))) {
    puts("That looks wrong. Good bye.");
    exit(1);
  }

  uint8_t digest[MD5_DIGEST_LENGTH];
  if (MD5((unsigned char *)response, strlen(response), digest) == nullptr) {
    puts("It's me, not you. Good bye.");
    exit(1);
  }

  if (memcmp(prefix, digest, sizeof(prefix))) {
    puts("Wrong answer. Good bye.");
    exit(1);
  }
}

void read_usercode() {
  puts("What's the length of your payload?");

  char line[64];
  int length;
  if (fgets(line, 64, stdin) == nullptr ||
      sscanf(line, "%i", &length) != 1 ||
      length < 0 || length >= 0x10000) {
    puts("Sorry, I don't speak broken. Good bye.");
    exit(2);
  }

  if (fread(usercode, 1, length, stdin) != (size_t)length) {
    puts("Didn't receive all of the declared data. Good bye.");
    exit(3);
  }
}

void remove_flag() {
  memset(flag, 0 ,sizeof(flag));
}

void init_emu(emu8051 *emu) {
  emu->sfr_register_handler(0xfa, sfr_gpio_module);
  emu->sfr_register_handler(0xfb, sfr_gpio_module);
  emu->sfr_register_handler(0xfc, sfr_i2c_module);
  emu->sfr_register_handler(0xfd, sfr_character_output);
  emu->sfr_register_handler(0xfe, sfr_debug_print);
  emu->sfr_register_handler(0xff, sfr_done_marker);
}

int main() {
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  read_proof_of_work();
  read_usercode();
  read_firmware();
  read_flag();

  dev_i2c = seeprom_new();
  seeprom_write_scl(dev_i2c, true);
  seeprom_write_sda(dev_i2c, true);

  {
    puts("Executing firmware...");
    emu8051 emu;
    init_emu(&emu);

    emu.mem_write(
      emu8051::mem_type_t::PMEM, /*addr=*/0, firmware, sizeof(firmware));

    emu.mem_write(
      emu8051::mem_type_t::XRAM, /*addr=*/0xff00, flag, sizeof(flag));
    memset(flag, 0, sizeof(flag));

    // Execute the firmware (no limit).
    done_marker = false;
    while (!done_marker) {
      emu.execute(1);
    }
  }

  remove_flag();

  {
    puts("Executing usercode...");
    emu8051 emu;
    init_emu(&emu);

    emu.mem_write(
      emu8051::mem_type_t::PMEM, /*addr=*/0, usercode, sizeof(usercode));

    // Execute the usercode (100k instruction limti).
    const int kUserCodeCycleLimit = 100000;
    done_marker = false;
    for (int i = 0; i < kUserCodeCycleLimit && !done_marker; i++) {
      emu.execute(1);
    }
  }

  seeprom_free(dev_i2c);

  puts("\nClean exit.");
  return 0;
}
