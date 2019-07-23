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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <seeprom.h>

#include <string>
#include <vector>

static const uint8_t kMemoryControlWrite = 0b10100000;
static const uint8_t kMemoryControlRead = 0b10100001;
static const uint8_t kSecureControl = 0b01010000;

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

static bool write_secure_mask(struct seeprom *dev, const uint8_t mask) {
  send_start(dev);
  send_byte(dev, kSecureControl | (mask & 0b1111));
  return recv_ack(dev);
}

static bool write_byte(struct seeprom *dev, const uint8_t address, const uint8_t v) {
  send_start(dev);
  send_byte(dev, kMemoryControlWrite);
  if (!recv_ack(dev)) {
    return false;
  }
  send_byte(dev, address);
  if (!recv_ack(dev)) {
    return false;
  }
  send_byte(dev, v);
  return recv_ack(dev);
}

static bool read_byte(struct seeprom *dev, const uint8_t address, uint8_t *out) {
  send_start(dev);
  send_byte(dev, kMemoryControlWrite);
  if (!recv_ack(dev)) {
    return false;
  }
  send_byte(dev, address);
  if (!recv_ack(dev)) {
    return false;
  }
  send_start(dev);
  send_byte(dev, kMemoryControlRead);
  if (!recv_ack(dev)) {
    return false;
  }
  *out = recv_byte(dev);
  if(!recv_ack(dev)) {
    return false;
  }
  send_stop(dev);
  return true;
}

static bool write_bytes(struct seeprom *dev, const uint8_t address,
    const std::vector<uint8_t> &data) {
  send_start(dev);
  send_byte(dev, kMemoryControlWrite);
  if (!recv_ack(dev)) {
    return false;
  }
  send_byte(dev, address);
  if (!recv_ack(dev)) {
    return false;
  }
  for (auto v : data) {
    send_byte(dev, v);
    if (!recv_ack(dev)) {
      return false;
    }
  }
  send_stop(dev);
  return true;
}

static bool read_bytes(struct seeprom *dev, const uint8_t address,
    std::vector<uint8_t> *out) {
  send_start(dev);
  send_byte(dev, kMemoryControlWrite);
  if (!recv_ack(dev)) {
    return false;
  }
  send_byte(dev, address);
  if (!recv_ack(dev)) {
    return false;
  }
  for (auto &i : *out) {
    i = recv_byte(dev);
    if (!recv_ack(dev)) {
      return false;
    }
  }
  send_stop(dev);
  return true;
}

int main(int argc, char **argv) {
  struct seeprom *dev = seeprom_new();

  const std::string flag = "gctf{flag_rom_and_on_and_on}";
  std::vector<uint8_t> flagv(flag.begin(), flag.end());

  // Write some bytes.
  if (!write_bytes(dev, 64, flagv)) {
    printf("Failed to write initial value.\n");
    return -1;
  }

  if (!write_byte(dev, 63, 'Z')) {
    printf("Failed to write random byte.\n");
    return -1;
  }

  // Secure some banks.
  write_secure_mask(dev, 0b1110);

  {
    uint8_t v;
    if (read_byte(dev, 64, &v)) {
      printf("read_byte in secure bank shouldn't succeed\n");
      return -1;
    }
  }

  {
    std::vector<uint8_t> v(2);
    if (read_bytes(dev, 63, &v)) {
      printf("read_bytes from insecure to secure shouldn't succeed\n");
      return -1;
    }
  }

  {
    send_start(dev);
    send_byte(dev, kMemoryControlWrite);
    recv_ack(dev);
    send_byte(dev, 64);
    recv_ack(dev);
    send_start(dev);
    send_byte(dev, kMemoryControlRead);
    recv_ack(dev);
    if (recv_byte(dev) == flag[0]) {
      printf("bypassing address check shouldn't succeed\n");
      return -1;
    }
  }

  {
    std::vector<uint8_t> v(flag.size() + 1);
    send_start(dev);
    send_byte(dev, kMemoryControlWrite);
    if (!recv_ack(dev)) {
      printf("failed to start memory control write\n");
      return -1;
    }
    send_byte(dev, 63);
    if (!recv_ack(dev)) {
      printf("failed to write insecure address\n");
      return -1;
    }
    send_start(dev);
    send_byte(dev, kSecureControl | 0b1111);
    if (!recv_ack(dev)) {
      printf("failed to write to secure control\n");
      return -1;
    }
    send_start(dev);
    send_byte(dev, kMemoryControlRead);
    if (!recv_ack(dev)) {
      printf("failed to start reading\n");
      return -1;
    }
    for (unsigned int i = 0; i < v.size(); i++) {
      v[i] = recv_byte(dev);
      if (!recv_ack(dev)) {
        printf("failed to receive byte %d\n", i);
        return -1;
      }
    }
    v.push_back('\0');
    printf("Read: %s\n", v.data() + 1);
  }

  seeprom_free(dev);
}
