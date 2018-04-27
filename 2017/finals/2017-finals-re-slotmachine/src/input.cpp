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



#include "input.h"
#include "pin_configuration.h"

#include <avr/io.h>
#include <util/delay.h>

#ifndef MODEL
#error "No model defined"
#endif

#if MODEL != 1 && MODEL != 2 && MODEL != 3 && MODEL != 4
#error "Invalid model specified"
#endif

constexpr uint8_t DEBOUNCE_TIME = 100; // in ms

namespace Input {

void init() {
    // Configure all button pins as input with pull-op resistors
    DDRB &= ~(PortB::BTN_0 | PortB::BTN_1);
    PORTB |= PortB::BTN_0 | PortB::BTN_1;

    DDRC &= ~(PortC::BTN_2 | PortC::BTN_3 | PortC::BTN_4);
    PORTC |= PortC::BTN_2 | PortC::BTN_3 | PortC::BTN_4;

    DDRD &= ~(PortD::BTN_5 | PortD::BTN_6 | PortD::BTN_7 | PortD::BTN_8 |
              PortD::BTN_9 | PortD::BTN_10 | PortD::BTN_11);
    PORTD |= PortD::BTN_5 | PortD::BTN_6 | PortD::BTN_7 | PortD::BTN_8 |
             PortD::BTN_9 | PortD::BTN_10 | PortD::BTN_11;

// Override ground with model specfic values
#if MODEL == 0
    // Dev board, no GND/VCC pin required.

#elif MODEL == 1
    // Slot machine (red one)
    /*
    Pin mapping:
    [GND] [P1] [P2] [P3] [P4] [P6] [P5] [GND] @
    GND: 25 (PC2) + 5 (PD3)
    P1: 24
    P2: 21
    P3: 9
    P4: 10
    P5: 6
    P6: 11
     */
    // Configure two pins as GND output
    DDRC |= 1 << PC2;
    PORTC &= ~(1 << PC2);
    DDRD |= 1 << PD3;
    PORTD &= ~(1 << PD3);
#elif MODEL == 2
    // Poker machine 1 (the red one)
    DDRC |= 1 << PC2;
    PORTC &= ~(1 << PC2);

    DDRD |= 1 << PD5;
    PORTD &= ~(1 << PD5);
#elif MODEL == 3
    // Poker machine 2
    // 25 GND, everything else input
    DDRC |= 1 << PC2;
    PORTC &= ~(1 << PC2);
#elif MODEL == 4
    DDRD |= 1 << PD7;
    PORTD &= ~(1 << PD7);
#endif
}

uint8_t attiny88_pin_nr_to_reg(uint8_t nr) {
    if ((nr >= 2 && nr <= 6) || (nr >= 11 && nr <= 13)) {
        return PIND;
    }
    if ((nr >= 23 && nr <= 28) || (nr == 1 || nr == 21)) {
        return PINC;
    }
    if ((nr >= 14 && nr <= 19) || (nr == 9 || nr == 10)) {
        return PINB;
    }

    return 0;
}

constexpr uint8_t attiny88_pin_nr_to_bit(uint8_t nr) {
    if (nr == 14 || nr == 23 || nr == 2)
        return PD0;
    if (nr == 15 || nr == 24 || nr == 3)
        return PD1;
    if (nr == 16 || nr == 25 || nr == 4)
        return PD2;
    if (nr == 17 || nr == 26 || nr == 5)
        return PD3;
    if (nr == 18 || nr == 27 || nr == 6)
        return PD4;
    if (nr == 19 || nr == 28 || nr == 11)
        return PD5;
    if (nr == 9 || nr == 1 || nr == 12)
        return PD6;
    if (nr == 10 || nr == 21 || nr == 13)
        return PD7;
    return 0;
}

bool attiny88_is_button_pressed(uint8_t pin_nr) {
    bool state =
        attiny88_pin_nr_to_reg(pin_nr) & (1 << attiny88_pin_nr_to_bit(pin_nr));
    if (state) {
        return false;
    }

    while (!state) {
        _delay_ms(DEBOUNCE_TIME);
        state = attiny88_pin_nr_to_reg(pin_nr) &
                (1 << attiny88_pin_nr_to_bit(pin_nr));
    }
    return true;
}

constexpr uint8_t conn_to_pin_map[] = {13, 2,  3, 4,  5,  6,
                                       11, 10, 9, 21, 24, 25};

bool is_button_pressed(uint8_t idx) {
    // TODO: use conn_to_pin_map for each case to keep the readability up
    uint8_t button_pins[5] = {
#if MODEL == 1
        24,
        21,
        9,
        10,
        11
#elif MODEL == 2
        21,
        10,
        6,
        3,
        13
#elif MODEL == 3
        4,
        6,
        10,
        21,
        24
#elif MODEL == 4
        conn_to_pin_map[8],
        conn_to_pin_map[6],
        conn_to_pin_map[4],
        conn_to_pin_map[2],
        conn_to_pin_map[1]
#else
#error "Not supported"
#endif
    };
    if (idx > sizeof(button_pins)) {
        return false;
    }

    return attiny88_is_button_pressed(button_pins[idx]);
}

bool is_spin_pressed() {
    return is_button_pressed(1);
}

bool is_bet_pressed() {
    return is_button_pressed(0);
}

} // namespace Input
