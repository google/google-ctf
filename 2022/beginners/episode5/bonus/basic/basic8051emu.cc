// Copyright 2022 Google LLC
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
#include <array>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <NetSock.h>
#include "emu8051/emu8051.h"
#include "serial.h"

volatile bool exit_flag;
volatile bool alarm_flag;

// Device Tree (only ones relevant to the challenge):
//   XRAM MMIO
//   |
//   + LAMP (write-only; 1 byte)
//   |
//   + REG (write-only; 1 byte)
//   |
//   + ROUTER (write-only)
//     |
//     + LAMP (read/write; 1 byte)
//     |
//     + REG (read/write; 1 byte)
//     |
//     + ADDER (read/write; 3 bytes)
//     |
//     + FLAGROM (read-only; 256 bytes)

// NOTE: LAMP is called IO externally.

const int XRAM_MMIO_LAMP = 23;  // Always returns 0xff. Lamp is at bit 6.

const int XRAM_MMIO_REG = 7;  // An 8-bit write-only register.
                              // Always returns 0xff.

const int XRAM_MMIO_ROUTER_SRC_DEV = 80;
const int XRAM_MMIO_ROUTER_SRC_REG = 81;
const int XRAM_MMIO_ROUTER_DST_DEV = 82;
const int XRAM_MMIO_ROUTER_DST_REG = 83;
const int XRAM_MMIO_ROUTER_CTRL    = 84;

const int BUS_DEV_LAMP = 15;
const int BUS_REG_LAMP_STATE = 0;

const int BUS_DEV_REG = 22;
const int BUS_REG_REG_VALUE = 0;

const int BUS_DEV_ADDER = 37;
const int BUS_REG_ADDER_A = 0;
const int BUS_REG_ADDER_B = 1;
const int BUS_REG_ADDER_RES = 2;

const int BUS_DEV_FLAGROM = 88;
// Register number is the number of memory cell.

// Used only as source port, doesn't receive packets.
const constexpr unsigned short BASICEMU_UDP_PORT = 23411;

const constexpr unsigned short BASIC_UDP_PORT = 23400;

NetSock *lamp_sock;

static uint8_t lamp_reg;
static uint8_t reg_reg;
static uint8_t adder_a;
static uint8_t adder_b;
static uint8_t flagrom[256];

static uint8_t router_src_dev;
static uint8_t router_src_reg;
static uint8_t router_dst_dev;
static uint8_t router_dst_reg;

//#define DEBUG

void lamp_write(uint8_t value);
bool router_xram_mmio_ctrl(emu8051 */*emu*/, emu8051::access_type_t access_type,
                   uint16_t /*addr*/, uint8_t *value,
                   void */*user_data*/) {
  if (access_type == emu8051::access_type_t::READ) {
    *value = 0;
    return true;
  }

  if ((*value & 1) == 0) {
    return true;
  }

  uint8_t acc = 0;

#ifdef DEBUG
  fprintf(stderr, "ROUTER: ");
#endif

  // Read value.
  switch (router_src_dev) {
    case BUS_DEV_LAMP:
      if (router_src_reg == BUS_REG_LAMP_STATE) {
        acc = lamp_reg;
#ifdef DEBUG
        fprintf(stderr, "lamp_reg");
#endif
      }
      break;

    case BUS_DEV_REG:
      if (router_src_reg == BUS_REG_REG_VALUE) {
        acc = reg_reg;
#ifdef DEBUG
        fprintf(stderr, "reg_reg");
#endif
      }
      break;

    case BUS_DEV_ADDER:
      if (router_src_reg == BUS_REG_ADDER_A) {
        acc = adder_a;
#ifdef DEBUG
        fprintf(stderr, "adder_a");
#endif
      } else if (router_src_reg == BUS_REG_ADDER_B) {
        acc = adder_b;
#ifdef DEBUG
        fprintf(stderr, "adder_b");
#endif
      } else if (router_src_reg == BUS_REG_ADDER_RES) {
        acc = adder_a + adder_b;
#ifdef DEBUG
        fprintf(stderr, "adder_res");
#endif
      }
      break;

    case BUS_DEV_FLAGROM:
      acc = flagrom[router_src_reg];
#ifdef DEBUG
        fprintf(stderr, "flagrom");
#endif
      break;
  }

#ifdef DEBUG
  fprintf(stderr, "--(%u)-->", acc);
#endif

  // Write accumulated value.
  switch (router_dst_dev) {
    case BUS_DEV_LAMP:
      if (router_dst_reg == BUS_REG_LAMP_STATE) {
        lamp_write(acc);
#ifdef DEBUG
        fprintf(stderr, "lamp_reg");
#endif
      }
      break;

    case BUS_DEV_REG:
      if (router_dst_reg == BUS_REG_REG_VALUE) {
        reg_reg = acc;
#ifdef DEBUG
        fprintf(stderr, "reg_reg");
#endif
      }
      break;

    case BUS_DEV_ADDER:
      if (router_dst_reg == BUS_REG_ADDER_A) {
        adder_a = acc;
#ifdef DEBUG
      fprintf(stderr, "adder_a");
#endif
      } else if (router_dst_reg == BUS_REG_ADDER_B) {
        adder_b = acc;
#ifdef DEBUG
      fprintf(stderr, "adder_b");
#endif
      } else if (router_dst_reg == BUS_REG_ADDER_RES) {
#ifdef DEBUG
      fprintf(stderr, "adder_res???");
#endif
        // Ignore.
      }
      break;

    case BUS_DEV_FLAGROM:
#ifdef DEBUG
      fprintf(stderr, "flagrom???");
#endif
      // It's read-only.
      break;
  }

#ifdef DEBUG
  fprintf(stderr, "\n");
#endif

  return true;
}

bool router_xram_mmio_reg(emu8051 */*emu*/, emu8051::access_type_t access_type,
                   uint16_t addr, uint8_t *value,
                   void */*user_data*/) {

  if (access_type == emu8051::access_type_t::READ) {
    switch (addr) {
      case XRAM_MMIO_ROUTER_SRC_DEV: *value = router_src_dev; break;
      case XRAM_MMIO_ROUTER_SRC_REG: *value = router_src_reg; break;
      case XRAM_MMIO_ROUTER_DST_DEV: *value = router_dst_dev; break;
      case XRAM_MMIO_ROUTER_DST_REG: *value = router_dst_reg; break;
      default:
        *value = 0xff;  // ???
        break;
    }
    return true;
  }

  switch (addr) {
    case XRAM_MMIO_ROUTER_SRC_DEV: router_src_dev = *value; break;
    case XRAM_MMIO_ROUTER_SRC_REG: router_src_reg = *value; break;
    case XRAM_MMIO_ROUTER_DST_DEV: router_dst_dev = *value; break;
    case XRAM_MMIO_ROUTER_DST_REG: router_dst_reg = *value; break;
  }

  return true;
}

bool reg_xram_mmio(emu8051 */*emu*/, emu8051::access_type_t access_type,
                 uint16_t /*addr*/, uint8_t *value,
                 void */*user_data*/) {
  if (access_type == emu8051::access_type_t::READ) {
    *value = 0;
    return true;
  }

  reg_reg = *value;
  return true;
}

void lamp_on() {
  lamp_sock->WriteUDP("127.0.0.1", BASIC_UDP_PORT, "\x01\x01", 2);
}

void lamp_off() {
  lamp_sock->WriteUDP("127.0.0.1", BASIC_UDP_PORT, "\x01\x00", 2);
}

void lamp_write(uint8_t value) {
  lamp_reg = value;

  if ((value & 0x40)) {
    lamp_on();
  } else {
    lamp_off();
  }
}

bool lamp_xram_mmio(emu8051 */*emu*/, emu8051::access_type_t access_type,
                 uint16_t /*addr*/, uint8_t *value,
                 void */*user_data*/) {
  if (access_type == emu8051::access_type_t::READ) {
    *value = 0xff;
    return true;
  }

  lamp_write(*value);
  return true;
}

void sig_handler(int /*signum*/) {
  exit_flag = true;
  alarm_flag = true;
}

bool sfr_poweroff(
    emu8051 */*emu*/,
    emu8051::access_type_t access_type,
    emu8051::address_type_t /*addr_type*/, uint8_t /*addr*/,
    uint8_t *value, void */*user_data*/) {
  if (access_type == emu8051::access_type_t::READ) {
    *value = 0;
    return true;
  }

  exit_flag = true;
  return true;
}

bool sfr_powersave(
    emu8051 */*emu*/,
    emu8051::access_type_t /*access_type*/,
    emu8051::address_type_t /*addr_type*/, uint8_t /*addr*/,
    uint8_t */*value*/, void */*user_data*/) {
  usleep(100 * 1000);  // Sleep for 100ms.
  return true;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: basic8051emu <file.bas>\n");
    return 1;
  }

  // Setup networking and standard output.
  NetSock::InitNetworking();
  NetSock lamp_udp_sock;
  if (!lamp_udp_sock.ListenUDP(BASICEMU_UDP_PORT, "127.0.0.1")) {
    puts("ERROR CONTACT ADMIN (CODE 477)");
    return 1;
  }
  lamp_sock = &lamp_udp_sock;

  setvbuf(stdout, NULL, _IONBF, 0);

  // Load flag.
  FILE *f = fopen("flag.txt", "r");
  if (f == nullptr) {
    puts("ERROR CONTACT ADMIN (CODE 133)");
    return 1;
  }
  fread(flagrom, 1, sizeof(flagrom), f);
  fclose(f);

  // Setup emulator.
  emu8051 emu;
  SerialDevice serial(&emu);

  // Load firmware (uBASIC interpreter).
  f = fopen("firmware.iram", "rb");
  if (f == nullptr) {
    fprintf(stderr,
            "CRITICAL ERROR: Firmware file not found\n");
    return 1;
  }

  uint8_t pmem_image[0x10000]{};
  size_t firmware_sz = fread(pmem_image, 1, sizeof(pmem_image), f);
  fclose(f);

  emu.mem_write(emu8051::mem_type_t::PMEM, /*addr=*/0, pmem_image, firmware_sz);

  // Load the BASIC source code to execute.
  f = fopen(argv[1], "r");
  if (f == nullptr) {
    fprintf(stderr,
            "CRITICAL ERROR: BAS file not found\n");
    return 2;
  }
  char bas_prog[0x8000]{};
  size_t bas_sz = fread(bas_prog, 1, sizeof(bas_prog), f);
  fclose(f);

  emu.mem_write(emu8051::mem_type_t::XRAM, /*addr=*/0x8000, bas_prog, bas_sz);

  emu.sfr_register_handler(0xff, sfr_poweroff, nullptr);
  emu.sfr_register_handler(0xfe, sfr_powersave, nullptr);

  // Register XRAM MMIO.
  emu.xram_register_handler(XRAM_MMIO_LAMP, lamp_xram_mmio);
  emu.xram_register_handler(XRAM_MMIO_REG, reg_xram_mmio);
  emu.xram_register_handler(XRAM_MMIO_ROUTER_SRC_DEV, router_xram_mmio_reg);
  emu.xram_register_handler(XRAM_MMIO_ROUTER_SRC_REG, router_xram_mmio_reg);
  emu.xram_register_handler(XRAM_MMIO_ROUTER_DST_DEV, router_xram_mmio_reg);
  emu.xram_register_handler(XRAM_MMIO_ROUTER_DST_REG, router_xram_mmio_reg);
  emu.xram_register_handler(XRAM_MMIO_ROUTER_CTRL, router_xram_mmio_ctrl);

  // Run stuff.
  signal(SIGALRM, sig_handler);
  alarm(20);

  for (int instruction_counter = 0;;) {
    if (instruction_counter == 5000) {
      usleep(6 * 1000);  // Yield from time to time.
      instruction_counter = 0;
    } else {
      instruction_counter++;
    }

    emu.execute(1);

    if (exit_flag) {
      break;
    }
  }

  if (alarm_flag) {
    puts("STOPPED (20sec limit)");
  }

  return 0;
}
