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

#include "seeprom.h"

#include "obj_dir/Vseeprom.h"

struct seeprom {
  Vseeprom *dev_;
};

struct seeprom *seeprom_new() {
  struct seeprom *dev = new(struct seeprom);
  dev->dev_ = new Vseeprom();
  return dev;
}

void seeprom_free(struct seeprom *dev) {
  delete dev->dev_;
  delete dev;
}

void seeprom_toggle_clock(struct seeprom *dev) {
  for (int i = 0; i < 2; i++) {
    dev->dev_->i_clk = 0;
    dev->dev_->eval();
    dev->dev_->i_clk = 1;
    dev->dev_->eval();
  }
}

void seeprom_write_scl(struct seeprom *dev, bool scl) {
  dev->dev_->i_i2c_scl = scl;
  seeprom_toggle_clock(dev);
}

void seeprom_write_sda(struct seeprom *dev, bool sda) {
  dev->dev_->i_i2c_sda = sda;
  seeprom_toggle_clock(dev);
}

bool seeprom_read_sda(struct seeprom *dev) {
  return dev->dev_->o_i2c_sda;
}
