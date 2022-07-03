// Copyright 2022 Google LLC
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
#include <array>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <signal.h>
#include "emu8051/emu8051.h"
#include "serial.h"
#include "flagrom.h"
#include "i2cbus.h"
#include "fakei2cdev.h"
#include "progeeprom.h"

volatile bool exit_flag;
volatile bool alarm_flag;

void sig_handler(int /*signum*/) {
  exit_flag = true;
  alarm_flag = true;
}

bool sfr_poweroff(
    emu8051 */*emu*/,
    emu8051::access_type_t access_type,
    emu8051::address_type_t /*addr_type*/, uint8_t /*addr*/,
    uint8_t *value, void */*user_data*/) {
  if (access_type == emu8051::access_type_t::READ) {
    *value = 0;
    return true;
  }

  exit_flag = true;
  return true;
}

bool sfr_powersave(
    emu8051 */*emu*/,
    emu8051::access_type_t /*access_type*/,
    emu8051::address_type_t /*addr_type*/, uint8_t /*addr*/,
    uint8_t */*value*/, void */*user_data*/) {
  usleep(100 * 1000);  // Sleep for 100ms.
  return true;
}

int main() {
  // Disable buffering, just to make life easier for players.
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);

  emu8051 emu;
  SerialDevice serial(&emu);
  FlagROMDevice flagrom(&emu, "flag");

  I2CController i2cbus(&emu);
  FakeI2CDevices fakedevs(&emu, &i2cbus);

  DualEEPROMDevice progeeprom(&emu, &i2cbus, 33);
  const size_t progeeprom_sz = 32768 / 8;
  progeeprom.set_capacity(progeeprom_sz);

  FILE *f = fopen("firmware.iram", "rb");
  if (f == nullptr) {
    fprintf(stderr,
            "CRITICAL ERROR: Firmware file not found (notify CTF admins)\n");
    return 1;
  }

  uint8_t pmem_image[0x10000];
  memset(pmem_image, 0xff, sizeof(pmem_image));
  size_t firmware_sz = fread(pmem_image, 1, sizeof(pmem_image), f);
  fclose(f);

  if (firmware_sz > progeeprom_sz) {
    fprintf(stderr, "CRITICAL ERROR: Firmware larger than ProgEEPROM\n");
    return 1;
  }
  progeeprom.store_at(0, pmem_image, progeeprom_sz);

  emu.sfr_register_handler(0xff, sfr_poweroff, nullptr);
  emu.sfr_register_handler(0xfe, sfr_powersave, nullptr);

  signal(SIGALRM, sig_handler);
  alarm(120);

  int instruction_counter = 0;
  for (;;) {
    if (instruction_counter == 1000) {
      usleep(6 * 1000);  // Yield from time to time.
      instruction_counter = 0;
    } else {
      instruction_counter++;
    }

    emu.execute(1);

    if (exit_flag) {
      break;
    }
  }

  if (alarm_flag) {
    puts("exiting (device execution time limited to 120 seconds)");
  } else {
    puts("exiting (device powered off)");
  }

  return 0;
}
