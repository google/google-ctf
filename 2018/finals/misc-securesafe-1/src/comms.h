/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#pragma once

#include <avr/io.h>

// no cstdint for avr-g++ :/
#include <stdint.h>
#include <stdio.h>

class Comms {
 public:
  virtual void transmit(uint8_t byte) = 0;
  virtual uint8_t receive() = 0;
};

class USART : public Comms {
  // RX (D0), TX (D1).
 public:
  USART(uint32_t baud) {
    // Set pins to the right modes.
    DDRD |= (1 << PD1);
    DDRD &= ~(1 << PD0);

    // Setup USART
    uint16_t ubrr = calc_ubrr(baud);
    UBRR0H = ubrr >> 8;
    UBRR0L = ubrr;

    // Enable RX/TX
    UCSR0B = (1 << RXEN0) | (1 << TXEN0);

    // 8bit data 1bit stop
    UCSR0C = (1 << UCSZ00) | (1 << UCSZ01);
  }

  void transmit(uint8_t byte) {
    // Wait until previous byte was transmitted
    while (!(UCSR0A & (1 << UDRE0))) {
      // Busy wait.
    }
    UDR0 = byte;
  }

  uint8_t receive() {
    while (!((UCSR0A) & (1 << RXC0))) {
      // Busy wait.
    }
    return UDR0;
  }

 private:
  static uint16_t calc_ubrr(uint32_t baud) { return ((F_CPU >> 4) / baud - 1); }
};

void send_string(Comms *comms, const char *str) {
  size_t i = 0;
  while (str[i]) {
    comms->transmit((uint8_t)str[i++]);
  }
}

