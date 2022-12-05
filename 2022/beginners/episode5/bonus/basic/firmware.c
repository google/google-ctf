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
#include "../third_party/ubasic/ubasic.h"

#ifndef NULL
#define NULL ((void*)0)
#endif

// Power controller.
__sfr __at(0xff) POWEROFF;
__sfr __at(0xfe) POWERSAVE;

// Serial controller.
__sfr __at(0xf2) SERIAL_OUT_DATA;
__sfr __at(0xf3) SERIAL_OUT_READY;

__xdata __at(0x8000) char program[0x8000];

void serial_print(const char *s) {
  while (*s) {
    while (!SERIAL_OUT_READY) {
      // Busy wait...
    }

    SERIAL_OUT_DATA = *s++;
  }
}

void putchar(int ch) {
  while (!SERIAL_OUT_READY) {
    // Busy wait...
  }

  SERIAL_OUT_DATA = (uint8_t)ch;
  //return (uint8_t)ch;
}

void serial_print_bytes(const char *s, int count) {
  while (count--) {
    while (!SERIAL_OUT_READY) {
      // Busy wait...
    }

    SERIAL_OUT_DATA = *s++;
  }
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

VARIABLE_TYPE peek_function(VARIABLE_TYPE addr) {
  __xdata uint8_t *p = (__xdata uint8_t*)addr;
  return *p;
}

void poke_function(VARIABLE_TYPE addr, VARIABLE_TYPE value) {
  __xdata uint8_t *p = (__xdata uint8_t*)addr;
  *p = value;
}

int main(void) {
  ubasic_init(program);

  do {
    ubasic_run();
  } while(!ubasic_finished());

  POWEROFF = 1;
  for (;;);  // Should never reach this loop.
}

// Ever heard of preprocessor-time linking?
#include "../third_party/ubasic/ubasic.c"
#include "../third_party/ubasic/tokenizer.c"
