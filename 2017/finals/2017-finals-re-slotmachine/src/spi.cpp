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



#include "spi.h"
#include "pin_configuration.h"

namespace SPI {

void init() {
    // MOSI, SCK, SS <- output
    DDRB |= PortB::MOSI | PortB::SCK | PortB::SS;
    // MISO <- input
    DDRB &= ~PortB::MISO;

    // Enable SPI
    SPCR = (1 << SPE) | (1 << MSTR);
}

uint8_t transceive(uint8_t val) {
    SPDR = val;
    while (!(SPSR & (1 << SPIF))) {
        // Busy loop
    }
    return SPDR;
}

} // namespace SPI
