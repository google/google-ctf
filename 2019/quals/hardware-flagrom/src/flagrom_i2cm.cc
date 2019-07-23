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

#include "flagrom_i2cm.h"
#include "flagrom.h"

static void send_start(struct seeprom *dev) {
  seeprom_write_scl(dev, 0);
  seeprom_write_sda(dev, 1);
  seeprom_write_scl(dev, 1);
  seeprom_write_sda(dev, 0);
}

static void send_stop(struct seeprom *dev) {
  seeprom_write_scl(dev, 0);
  seeprom_write_sda(dev, 0);
  seeprom_write_scl(dev, 1);
  seeprom_write_sda(dev, 1);
}

static void send_byte(struct seeprom *dev, const uint8_t v) {
  for (int i = 0; i < 8; i++) {
    seeprom_write_scl(dev, 0);
    seeprom_write_sda(dev, !!(v & (1 << (7 - i))));
    seeprom_write_scl(dev, 1);
  }
}

static uint8_t recv_byte(struct seeprom *dev) {
  uint8_t result = 0;
  for (int i = 0; i < 8; i++) {
    seeprom_write_scl(dev, 0);
    seeprom_write_scl(dev, 1);
    result = (result << 1) | seeprom_read_sda(dev);
  }
  return result;
}

static bool recv_ack(struct seeprom *dev) {
  seeprom_write_scl(dev, 0);
  seeprom_write_scl(dev, 1);
  return !seeprom_read_sda(dev);
}

bool sfr_i2c_module(
    emu8051 *emu,
    emu8051::access_type_t access_type,
    emu8051::address_type_t /*addr_type*/, uint8_t /*addr*/,
    uint8_t *value) {

  if (access_type == emu8051::access_type_t::READ) {
    // Normally this should return whether the I2C-M module is busy, but since
    // we cheat a little and clock the module separately than the CPU, this
    // module is technically never busy.
    *value = 0;
    return true;
  }

  if ((*value & 1) != 1) {
    // Weird. But whatever. It has to be a 1.
    return true;
  }

  struct req_t {
    /* XRAM:fe00 */ uint8_t addr;
    /* XRAM:fe01 */ uint8_t length;
    /* XRAM:fe02 */ uint8_t rw_mask;
    /* XRAM:fe03 */ uint8_t error_code;
                    uint8_t __padding[4];
    /* XRAM:fe08 */ uint8_t data[8];
  } __attribute__((packed));
  req_t req;
  static_assert(sizeof(req) == 16);

  emu->mem_read(emu8051::mem_type_t::XRAM, /*addr=*/0xfe00, &req, sizeof(req));

  do {
    // Sanity checks.
    if (req.length >= 8) {
      req.error_code = 1;
      break;
    }

    // In case there are no data to send, we still need to send the address (as
    // provided).
    if (req.length == 0) {
      send_start(dev_i2c);
      send_byte(dev_i2c, req.addr);
      if (recv_ack(dev_i2c)) {
        req.error_code = 0;  // Success.
      } else {
        req.error_code = 5;  // Fail.
      }
      break;
    }

    // There are multiple bytes to send/receive and we might need to switch
    // between reading and writing.
    req.addr &= 0xfe;  // Mask out the R/W bit.

    enum class req_type_t {
      NONE,
      WRITE,
      READ
    } last_req_type = req_type_t::NONE;

    bool ok = true;
    for (int i = 0; req.length > 0; i++) {
      req_type_t req_type =
          ((req.rw_mask >> i) & 1) == 0 ? req_type_t::WRITE : req_type_t::READ;

      // (Re)send the start bit and address if needed.
      if (req_type != last_req_type) {
        send_start(dev_i2c);
        send_byte(dev_i2c, req.addr | (int)(req_type == req_type_t::READ));
        if (!recv_ack(dev_i2c)) {
          req.error_code = 2;
          ok = false;
          break;
        }

        last_req_type = req_type;
      }

      if (req_type == req_type_t::READ) {
        req.data[i] = recv_byte(dev_i2c);
      } else {
        send_byte(dev_i2c, req.data[i]);
      }

      if (!recv_ack(dev_i2c)) {
        req.error_code = 3;
        ok = false;
        break;
      }

      req.length--;
    }

    if (ok) {
      req.error_code = 0;
    }
  } while (0);

  // Stop the transfer.s
  send_stop(dev_i2c);

  // Write back the structure.
  emu->mem_write(emu8051::mem_type_t::XRAM, /*addr=*/0xfe00, &req, sizeof(req));

  return true;
}
