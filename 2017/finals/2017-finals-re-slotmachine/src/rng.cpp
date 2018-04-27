// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.



#include <avr/interrupt.h>
#include <util/delay.h>

#include "ILI9225.h"

constexpr uint8_t required_samples_per_bit = 4;
static volatile uint8_t current_nr_of_samples = 0;
static volatile uint8_t current_timer_state = 100;
static volatile uint8_t nr_random_bits_available = 0;

ISR(WDT_vect) {
    current_timer_state ^= TCNT1L;
    current_nr_of_samples++;
    if (current_nr_of_samples >= required_samples_per_bit) {
        current_nr_of_samples = 0;
        uint8_t t = current_timer_state;
        current_timer_state = (t << 1) | (t >> 7);
        if (nr_random_bits_available < 8) {
            nr_random_bits_available++;
        }
    }
}

namespace RNG {
namespace Good {
void init() {
    // Cause interrupt on watchdog triggering + do not reset
    MCUSR = 0;
    WDTCSR |= (1 << WDCE) | (1 << WDE);
    WDTCSR = (1 << WDIE);

    // Enable timer 1
    TCCR1B = (1 << CS10);
}

uint8_t __attribute__((noinline)) get_u8() {
    while (nr_random_bits_available < 8) {
        // Busy loop
    }
    uint8_t r = current_timer_state;
    nr_random_bits_available = 0;

    return r;
}
} // namespace Good

namespace Bad {
static uint32_t state = 0;

// a used from glibc
constexpr uint32_t a = 1103515245;
constexpr uint32_t c = 31337;

void seed(uint32_t seed) {
    state = seed;
}

// Make RE easier
uint32_t __attribute__((noinline)) get_u32() {
    state = a * state + c;
    return state;
}

// Make RE easier
uint16_t __attribute__((noinline)) get_u16() {
    uint32_t r = get_u32();
    return (r & 0xFFFF) ^ (r >> 16);
}

void add_to_seed(uint32_t mod) {
    state += mod;
}
} // namespace Bad
} // namespace RNG
