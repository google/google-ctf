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

#ifndef SEEPROM_H_
#define SEEPROM_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct seeprom;
struct seeprom *seeprom_new();
void seeprom_free(struct seeprom *seeprom);

void seeprom_toggle_clock(struct seeprom *dev);
void seeprom_write_scl(struct seeprom *seeprom, bool scl);
void seeprom_write_sda(struct seeprom *seeprom, bool sda);
bool seeprom_read_sda(struct seeprom *seeprom);

#ifdef __cplusplus
}
#endif

#endif // SEEPROM_H_
