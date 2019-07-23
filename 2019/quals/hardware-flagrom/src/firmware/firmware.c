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

__sfr __at(0xff) POWEROFF;
__sfr __at(0xfe) DEBUG;
__sfr __at(0xfd) CHAROUT;
__xdata __at(0xff00) unsigned char FLAG[0x100];

__sfr __at(0xfa) RAW_I2C_SCL;
__sfr __at(0xfb) RAW_I2C_SDA;

// I2C-M module/chip control data structure.
__xdata __at(0xfe00) unsigned char I2C_ADDR; // 8-bit version.
__xdata __at(0xfe01) unsigned char I2C_LENGTH;  // At most 8 (excluding addr).
__xdata __at(0xfe02) unsigned char I2C_RW_MASK;  // 1 R, 0 W.
__xdata __at(0xfe03) unsigned char I2C_ERROR_CODE;  // 0 - no errors.
__xdata __at(0xfe08) unsigned char I2C_DATA[8];  // Don't repeat addr.
__sfr __at(0xfc) I2C_STATE;  // Read: 0 - idle, 1 - busy; Write: 1 - start

const SEEPROM_I2C_ADDR_MEMORY = 0b10100000;
const SEEPROM_I2C_ADDR_SECURE = 0b01010000;

void print(const char *str) {
  while (*str) {
    CHAROUT = *str++;
  }
}

void seeprom_wait_until_idle() {
  while (I2C_STATE != 0) {}
}

void seeprom_write_byte(unsigned char addr, unsigned char value) {
  seeprom_wait_until_idle();

  I2C_ADDR = SEEPROM_I2C_ADDR_MEMORY;
  I2C_LENGTH = 2;
  I2C_ERROR_CODE = 0;
  I2C_DATA[0] = addr;
  I2C_DATA[1] = value;
  I2C_RW_MASK = 0b00;  // 2x Write Byte

  I2C_STATE = 1;
  seeprom_wait_until_idle();
}

unsigned char seeprom_read_byte(unsigned char addr) {
  seeprom_wait_until_idle();

  I2C_ADDR = SEEPROM_I2C_ADDR_MEMORY;
  I2C_LENGTH = 2;
  I2C_ERROR_CODE = 0;
  I2C_DATA[0] = addr;
  I2C_RW_MASK = 0b10;  // Write Byte, then Read Byte

  I2C_STATE = 1;
  seeprom_wait_until_idle();

  if (I2C_ERROR_CODE != 0) {
    return 0;
  }

  return I2C_DATA[1];
}

void seeprom_secure_banks(unsigned char mask) {
  seeprom_wait_until_idle();

  I2C_ADDR = SEEPROM_I2C_ADDR_SECURE | (mask & 0b1111);
  I2C_LENGTH = 0;
  I2C_ERROR_CODE = 0;

  I2C_STATE = 1;
  seeprom_wait_until_idle();
}

void write_flag() {
  unsigned char i;
  print("[FW] Writing flag to SecureEEPROM...............");
  for (i = 0; FLAG[i] != '\0'; i++) {
    seeprom_write_byte(64 + i, FLAG[i]);
  }

  // Verify.
  for (i = 0; FLAG[i] != '\0'; i++) {
    if (seeprom_read_byte(64 + i) != FLAG[i]) {
      print("VERIFY FAIL\n");
      POWEROFF = 1;
    }
  }
  print("DONE\n");
}

void secure_banks() {
  unsigned char i;
  print("[FW] Securing SecureEEPROM flag banks...........");

  seeprom_secure_banks(0b0010);  // Secure 64-byte bank with the flag.

  // Verify that the flag can NOT be read.
  for (i = 0; FLAG[i] != '\0'; i++) {
    if (seeprom_read_byte(64 + i) == FLAG[i]) {
      print("VERIFY FAIL\n");
      POWEROFF = 1;
    }
  }

  print("DONE\n");
}

void remove_flag() {
  unsigned char i;
  print("[FW] Removing flag from 8051 memory.............");

  for (i = 0; FLAG[i] != '\0'; i++) {
    FLAG[i] = '\0';
  }

  print("DONE\n");
}

void write_welcome() {
  unsigned char i;
  const char *msg = "Hello there.";
  print("[FW] Writing welcome message to SecureEEPROM....");
  for (i = 0; msg[i] != '\0'; i++) {
    seeprom_write_byte(i, msg[i]);
  }

  // Verify.
  for (i = 0; msg[i] != '\0'; i++) {
    if (seeprom_read_byte(i) != (unsigned char)msg[i]) {
      print("VERIFY FAIL\n");
      POWEROFF = 1;
    }
  }
  print("DONE\n");
}

void main(void) {
  write_flag();
  secure_banks();
  remove_flag();
  write_welcome();
  POWEROFF = 1;
}
