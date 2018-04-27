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



#include "i2c.h"
#include "pin_configuration.h"

#include <util/twi.h>

namespace I2C {
static void wait() {
    while (!(TWCR & (1 << TWINT))) {
        // busy loop
    }
}

uint8_t init() {
/*
f_SCL = clk / (16 + (2 * TWBR * TWPS))
<=>
((clk / f_SCL) - 16) / 2 = TWBR * TWPS
 */
#ifndef I2C_USE_HIGHSPEED
    // 400kHz
    TWBR = ((F_CPU / 400000L) - 16) / 2;
    TWSR = 0;
#else
    // TODO: Am I doing this right?
    TWBR = ((F_CPU / 400000L) - 16) / 2;
    TWSR = 0;
    TWHSR |= (1 << 0);
#endif

    // Set with pullup resistors so that we don't need external ones
    DDRC |= PortC::I2C_CLK | PortC::I2C_DATA;
    PORTC |= PortC::I2C_CLK | PortC::I2C_DATA;
    return 0;
}

uint8_t start(uint8_t addr) {
    TWCR = (1 << TWINT) | (1 << TWSTA) | (1 << TWEN);
    wait();

    uint8_t status = TW_STATUS;
    switch (status) {
    case TW_START:
        break;
    case TW_REP_START:
        break;
    case TW_MT_ARB_LOST:
        return start(addr);
    default:
        return status;
        break;
    }

    TWDR = (addr << 1) | TW_WRITE;
    TWCR = (1 << TWINT) | (1 << TWEN);
    wait();

    uint8_t twst = TW_STATUS & 0xF8;
    if ((twst != TW_MT_SLA_ACK) && (twst != TW_MR_SLA_ACK)) {
        return (TWSR & 0xF8);
    }
    return 0;
}

uint8_t send(uint8_t data) {
    TWDR = data;
    TWCR |= (1 << TWINT);
    wait();
    if ((TWSR & 0xF8) != TW_MT_DATA_ACK) {
        return TWSR & 0xF8;
    }
    return 0;
}

void end() {
    TWCR = (1 << TWINT) | (1 << TWSTO) | (1 << TWEN);
}
} // namespace I2C
