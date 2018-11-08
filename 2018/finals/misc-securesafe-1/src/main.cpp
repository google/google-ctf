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
#include "comms.h"
#include "md5.h"

#include <avr/eeprom.h>
#include <avr/io.h>
#include <util/delay.h>

// no cstdint for avr-g++ :/
#include <stdio.h>
#include <stdlib.h>

void read_string(Comms *comms, uint8_t *buffer, size_t max_len);
void write_bytes(Comms *comms, uint8_t *buffer, size_t len);
void crypto_test(Comms *comms);
void timing_challenge(Comms *comms);

constexpr uint8_t LED_Rdy = 0;
constexpr uint8_t LED_Locked = 1;

void set_led(uint8_t led, bool status) {
  switch (led) {
    case 0: {
      if (!status) {
        PORTC |= (1 << PC0);
      } else {
        PORTC &= ~(1 << PC0);
      }
    } break;
    case 1: {
      if (!status) {
        PORTC |= (1 << PC1);
      } else {
        PORTC &= ~(1 << PC1);
      }
    } break;
    default:
      break;
  }
}

// BUG: We're not using update_byte here, so the eeprom will always get cleared
// (0xFF) before the actual byte (0x00) will be written -> eeprom glitching.
void eeprom_store(uint8_t v) { eeprom_write_byte((uint8_t *)0, v); }
uint8_t eeprom_read() { return eeprom_read_byte((uint8_t *)0); }

int main() {
  DDRC |= (1 << PC0) | (1 << PC1);
  // Disable LEDs.
  PORTC |= (1 << PC0) | (1 << PC1);

  // Slow down the startup a little.
  _delay_ms(1000);
  // Create a comms channel.
  USART comms(19200);

  send_string(&comms, "\r\nSMARTSAFE serial interface v1.22.6728\r\n");
  _delay_ms(100);

  // Lock the device on first boot.
  // Eeprom is cleared by default (meaning 0xFF at each position).
  // We want this challenge to be locked by default, so if a random position
  // (we picked 7 here) is 0xFF, this is the first boot and we should lock
  // the device.
  if (eeprom_read_byte((uint8_t *)7) != 0) {
    eeprom_store(0);
    eeprom_write_byte((uint8_t *)7, 0);
  }

  send_string(&comms, "Booting up\r\n");
  _delay_ms(500);

  uint8_t unlocked = eeprom_read();
  set_led(LED_Rdy, true);

  while (true) {
    set_led(LED_Locked, !unlocked);
    if (!unlocked) {
      send_string(&comms, "Device status: *** LOCKED ***\r\n");
    } else {
      send_string(&comms, "Device status: *** UNLOCKED ***\r\n");
#ifdef WITH_FLAG
      send_string(&comms, "  Your flag is CTF{D1stUrb4Nc3_1N_thE_EeProM}\r\n");
#else
      send_string(&comms, "  Your flag is <<here>>\r\n");
#endif
    }

    send_string(&comms, " [1] Cryptography test\r\n");
    send_string(&comms, " [2] (Un)Lock\r\n");
    send_string(&comms, " [3] Persist state\r\n");
    send_string(&comms, " > ");
    comms.transmit(0);  // Mark that we want input.

    uint8_t choice = comms.receive();
    if (choice == '1') {
      crypto_test(&comms);
    } else if (choice == '2') {
      send_string(&comms, "Enter your key to unlock the device\r\n");
      timing_challenge(&comms);
      // Function only returns if unlocked.

      // Leftover from previous version, only left here so that it
      // matches the rom dump.
      PORTD |= (1 << PD5);
    } else if (choice == '3') {
      send_string(&comms, "Persisting storage...");
      eeprom_store(unlocked);
      send_string(&comms, "done!\r\n");
    } else {
      send_string(&comms, "Invalid selection.\r\n");
    }
  }

  return 0;
}

void read_string(Comms *comms, uint8_t *buffer, size_t max_len) {
  size_t i = 0;
  while (i < max_len) {
    buffer[i] = comms->receive();
    if (buffer[i++] == 0) {
      break;
    }
  }
}

void write_bytes(Comms *comms, uint8_t *buffer, size_t len) {
  for (size_t i = 0; i < len; i++) {
    comms->transmit(buffer[i]);
  }
}

static volatile uint8_t secret_hash[16] =
#ifdef WITH_FLAG
    // md5('Md5Yo')
    {0xcc, 0x1a, 0xc1, 0x12, 0xf1, 0x6f, 0xfe, 0xb3,
     0x9b, 0xed, 0x42, 0x39, 0x95, 0xb3, 0xae, 0xea}
#else
    "PLACEHOLDER0123"
#endif
;

bool __attribute__((noinline)) is_correct__timing(volatile uint8_t *in) {
  // BUG: Timing attack.
  for (int j = 0; j < 16; j++) {
    volatile bool single_correct = true;
    for (volatile int i = 0; i < 100; i++) {
      single_correct &= secret_hash[j] == in[j];
      if (!single_correct) {
        return false;
      }
    }
  }

  return true;
}

void crypto_test(Comms *comms) {
  char buffer[16] = {};
  send_string(comms, "\r\nRaw crypto test - Input:\r\n> ");
  comms->transmit(0);

  // Get user input to hash.
  read_string(comms, (uint8_t *)buffer, sizeof(buffer) - 1);

  // Calculate hash.
  uint8_t *out = MD5::make_hash(buffer);

  // Send out the hash.
  write_bytes(comms, (uint8_t *)out, 4 * sizeof(uint32_t));
}

void timing_challenge(Comms *comms) {
  while (true) {
    char buffer[16] = {};
    send_string(comms, "\r\nUnlock key\r\n> ");
    comms->transmit(0);

    // Get user input to hash.
    read_string(comms, (uint8_t *)buffer, sizeof(buffer) - 1);

    // Calculate hash.
    uint8_t *out = MD5::make_hash(buffer);

    if (is_correct__timing(out)) {
      send_string(comms, "\r\nCorrect password, opening safe\r\n");
      _delay_ms(1000);
      send_string(comms, "Failed, error 42 - safe still locked\r\n");
      return;
    }

    send_string(comms, "Error, hash did not match.\r\n");

    _delay_ms(50);
  }
}

