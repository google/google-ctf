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
#include <stdint.h>
#include <stdbool.h>

#ifndef NULL
#define NULL ((void*)0)
#endif

// Secret ROM controller.
__sfr __at(0xee) FLAGROM_ADDR;
__sfr __at(0xef) FLAGROM_DATA;

// Serial controller.
__sfr __at(0xf2) SERIAL_OUT_DATA;
__sfr __at(0xf3) SERIAL_OUT_READY;
__sfr __at(0xfa) SERIAL_IN_DATA;
__sfr __at(0xfb) SERIAL_IN_READY;

// I2C DMA controller.
__sfr __at(0xe1) I2C_STATUS;
__sfr __at(0xe2) I2C_BUFFER_XRAM_LOW;
__sfr __at(0xe3) I2C_BUFFER_XRAM_HIGH;
__sfr __at(0xe4) I2C_BUFFER_SIZE;
__sfr __at(0xe6) I2C_ADDRESS;  // 7-bit address
__sfr __at(0xe7) I2C_READ_WRITE;

// Power controller.
__sfr __at(0xff) POWEROFF;
__sfr __at(0xfe) POWERSAVE;

const char *ALLOWED_I2C[] = {
  "101",  // Thermometers (4x).
  "108",  // Atmospheric pressure sensor.
  "110",  // Light sensor A.
  "111",  // Light sensor B.
  "119",  // Humidity sensor.
  NULL
};

int8_t i2c_write(int8_t port, uint8_t req_len, __xdata uint8_t *buf) {
  while (I2C_STATUS == 1) {
    POWERSAVE = 1;  // Enter power save mode for a few milliseconds.
  }

  I2C_BUFFER_XRAM_LOW = (uint8_t)(uint16_t)buf;
  I2C_BUFFER_XRAM_HIGH = (uint8_t)((uint16_t)buf >> 8);
  I2C_BUFFER_SIZE = req_len;
  I2C_ADDRESS = port;

  I2C_READ_WRITE = 0;  // Start write.

  int8_t status;
  while ((status = I2C_STATUS) == 1) {
    POWERSAVE = 1;  // Enter power save mode for a few milliseconds.
  }

  return status;
}

int8_t i2c_read(int8_t port, uint8_t req_len, __xdata uint8_t *buf) {
  while (I2C_STATUS == 1) {
    POWERSAVE = 1;  // Enter power save mode for a few milliseconds.
  }

  I2C_BUFFER_XRAM_LOW = (uint8_t)(uint16_t)buf;
  I2C_BUFFER_XRAM_HIGH = (uint8_t)((uint16_t)buf >> 8);
  I2C_BUFFER_SIZE = req_len;
  I2C_ADDRESS = port;

  I2C_READ_WRITE = 1;  // Start read.

  int8_t status;
  while ((status = I2C_STATUS) == 1) {
    POWERSAVE = 1;  // Enter power save mode for a few milliseconds.
  }

  return status;
}

const char *i2c_status_to_error(int8_t err) {
  switch (err) {
    case 0: return "i2c status: transaction completed / ready\n";
    case 1: return "i2c status: busy\n";
    case 2: return "i2c status: error - device not found\n";
    case 3: return "i2c status: error - device misbehaved\n";
  }

  return "i2c status: unknown error\n";
}

void serial_print(const char *s) {
  while (*s) {
    while (!SERIAL_OUT_READY) {
      // Busy wait...
    }

    SERIAL_OUT_DATA = *s++;
  }
}

char serial_read_char(void) {
  while (1) {
    if (SERIAL_IN_READY) {
      return (char)SERIAL_IN_DATA;
    }

    POWERSAVE = 1;  // Enter power save mode for a few milliseconds.
  }
}

struct tokenizer_st {
  char *ptr;
  int replaced;
};

void tokenizer_init(struct tokenizer_st *t, char *str) {
  t->ptr = str;
  t->replaced = 0x7fff;
}

char *tokenizer_next(struct tokenizer_st *t) {
  if (t->replaced != 0x7fff) {
    *t->ptr = (char)t->replaced;
  }

  while (*t->ptr == ' ') {
    t->ptr++;
  }

  if (*t->ptr == '\0') {
    return NULL;
  }

  char *token_start = t->ptr;
  for (;;) {
    char ch = *t->ptr;
    if (ch != ' ' && ch != '\0') {
      t->ptr++;
      continue;
    }

    t->replaced = *t->ptr;
    *t->ptr = '\0';
    return token_start;
  }
}

uint8_t str_to_uint8(const char *s) {
  uint8_t v = 0;
  while (*s) {
    uint8_t digit = *s++ - '0';
    if (digit >= 10) {
      return 0;
    }
    v = v * 10 + digit;
  }
  return v;
}

void uint8_to_str(char *buf, uint8_t v) {
  if (v >= 100) {
    *buf++ = '0' + v / 100;
  }

  if (v >= 10) {
    *buf++ = '0' + (v / 10) % 10;
  }

  *buf++ = '0' + v % 10;
  *buf = '\0';
}

bool is_port_allowed(const char *port) {
  for(const char **allowed = ALLOWED_I2C; *allowed; allowed++) {
    const char *pa = *allowed;
    const char *pb = port;
    bool allowed = true;
    while (*pa && *pb) {
      if (*pa++ != *pb++) {
        allowed = false;
        break;
      }
    }
    if (allowed && *pa == '\0') {
      return true;
    }
  }
  return false;
}

int8_t port_to_int8(char *port) {
  if (!is_port_allowed(port)) {
    return -1;
  }

  return (int8_t)str_to_uint8(port);
}

#define CMD_BUF_SZ 384
#define I2C_BUF_SZ 128
int main(void) {
  serial_print("Weather Station\n");

  static __xdata char cmd[CMD_BUF_SZ];
  static __xdata uint8_t i2c_buf[I2C_BUF_SZ];

  while (true) {
    serial_print("? ");

    int i;
    for (i = 0; i < CMD_BUF_SZ; i++) {
      char ch = serial_read_char();
      if (ch == '\n') {
        cmd[i] = '\0';
        break;
      }
      cmd[i] = ch;
    }

    if (i == CMD_BUF_SZ) {
      serial_print("-err: command too long, rejected\n");
      continue;
    }

    struct tokenizer_st t;
    tokenizer_init(&t, cmd);

    char *p = tokenizer_next(&t);
    if (p == NULL) {
      serial_print("-err: command format incorrect\n");
      continue;
    }

    bool write;
    if (*p == 'r') {
      write = false;
    } else if (*p == 'w') {
      write = true;
    } else {
      serial_print("-err: unknown command\n");
      continue;
    }

    p = tokenizer_next(&t);
    if (p == NULL) {
      serial_print("-err: command format incorrect\n");
      continue;
    }

    int8_t port = port_to_int8(p);
    if (port == -1) {
      serial_print("-err: port invalid or not allowed\n");
      continue;
    }

    p = tokenizer_next(&t);
    if (p == NULL) {
      serial_print("-err: command format incorrect\n");
      continue;
    }

    uint8_t req_len = str_to_uint8(p);
    if (req_len == 0 || req_len > I2C_BUF_SZ) {
      serial_print("-err: I2C request length incorrect\n");
      continue;
    }

    if (write) {
      for (uint8_t i = 0; i < req_len; i++) {
        p = tokenizer_next(&t);
        if (p == NULL) {
          break;
        }

        i2c_buf[i] = str_to_uint8(p);
      }

      int8_t ret = i2c_write(port, req_len, i2c_buf);
      serial_print(i2c_status_to_error(ret));
    } else {
      int8_t ret = i2c_read(port, req_len, i2c_buf);
      serial_print(i2c_status_to_error(ret));

      for (uint8_t i = 0; i < req_len; i++) {
        char num[4];
        uint8_to_str(num, i2c_buf[i]);
        serial_print(num);

        if ((i + 1) % 16 == 0 && i +1 != req_len) {
          serial_print("\n");
        } else {
          serial_print(" ");
        }
      }

      serial_print("\n-end\n");
    }
  }

  // Should never reach this place.
}
