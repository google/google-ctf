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



#include <stdint.h>

#include "ILI9225.h"
#include "item.h"
#include "rng.h"

#include <util/delay.h>

namespace Item {
constexpr uint16_t probability_table[] = {0, 0xFFFF - 655 - 3277 - 13763,
                                          0xFFFF - 655 - 3277, 0xFFFF - 655};
constexpr uint8_t num_entries =
    sizeof(probability_table) / sizeof(probability_table[0]);

constexpr type_t items[] = {None, Single, Double, Triple};

constexpr uint16_t points[] = {0, 100, 500, 1000};

static_assert(sizeof(items) / sizeof(type_t) == num_entries &&
                  sizeof(points) / sizeof(points[0]) == num_entries,
              "Fix your code!");

type_t get_random() {
    uint16_t v = RNG::Bad::get_u16();
    for (uint8_t n = num_entries - 1; n < num_entries; n--) {
        if (v >= probability_table[n]) {
            return items[n];
        }
    }
    return None;
}

uint16_t get_points(type_t item) {
    return points[item];
}
} // namespace Item
