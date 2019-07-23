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

#pragma once
// This emu is probably a study on defensive coding. But it actually is expected
// to run hostile code, so it has to be.
// Feel free to pass all complains to Gynvael Coldwind ;)
#include <stdint.h>
#include <array>
#include <utility>
#include "emu8051_opcodes.h"

class emu8051 {
 public:

  enum class access_type_t {
    READ,
    WRITE
  };

  enum class address_type_t {
    ADDR_BYTE,
    ADDR_BIT
  };

  // In case addr_type is set to ADDR_BIT, the handler should call the
  // convert_bit_address function to get the register and bit pair.
  typedef bool (*sfr_handler)(emu8051 *emu, access_type_t access_type,
                              address_type_t addr_type, uint8_t addr,
                              uint8_t *value);

  enum class mem_type_t {
    IRAM_DIRECT,  // Allows access to special registers.
    IRAM_INDIRECT,  // Allows access to top 128-bytes of IRAM.
    XRAM,
    PMEM
  };

  // Interrupt jump locations.
  const uint16_t INT_EXTERNAL0 = 0x0003;
  const uint16_t INT_EXTERNAL1 = 0x0013;
  const uint16_t INT_TIMER0 = 0x000B;
  const uint16_t INT_TIMER1 = 0x001B;

  // Other values, not used in this emu:
  /*
  const uint16_t INT_SERIAL = 0x0023;
  */

  // Memory mapped registers addresses (general and SFR).
  const uint8_t SP = 0x81;  // Stack pointer (1 byte).
  const uint8_t DPTR = 0x82;  // Data pointer (2 bytes).
  const uint8_t DPL = 0x82;  // Data pointer (low byte).
  const uint8_t DPH = 0x83;  // Data pointer (high byte).
  const uint8_t PSW = 0xD0;  // Program status word (1 byte).
  const uint8_t A = 0xE0; // Accumulator (1 byte).
  const uint8_t B = 0xF0; // Register (1 byte).

  const uint8_t P0 = 0x80; // Port 0 (1 byte).
  const uint8_t P1 = 0x90; // Port 0 (1 byte).
  const uint8_t P2 = 0xA0; // Port 0 (1 byte).
  const uint8_t P3 = 0xB0; // Port 0 (1 byte).

  // PSW bitmap.
  const uint8_t PSW_P = 0; // PSW Parity flag (1 bit).
  const uint8_t PSW_UD = 1; // PSW User definable flag (1 bit).
  const uint8_t PSW_OV = 2; // PSW Overflow flag (1 bit).
  const uint8_t PSW_RS = 3; // PSW Register bank select (2 bits).
  const uint8_t PSW_RS0 = 3; // PSW RS low bit.
  const uint8_t PSW_RS1 = 4; // PSW RS high bit.
  const uint8_t PSW_F0 = 5; // PSW Flag 0 (1 bit).
  const uint8_t PSW_AC = 6; // PSW Auxiliary Carry flag (1 bit).
  const uint8_t PSW_C = 7; // PSW Carry flag (1 bit).

  const uint8_t BITADDR_PSW_P = 0xD0;
  const uint8_t BITADDR_PSW_UD = 0xD1;
  const uint8_t BITADDR_PSW_OV = 0xD2;
  const uint8_t BITADDR_PSW_RS0 = 0xD3;
  const uint8_t BITADDR_PSW_RS1 = 0xD4;
  const uint8_t BITADDR_PSW_F0 = 0xD5;
  const uint8_t BITADDR_PSW_AC = 0xD6;
  const uint8_t BITADDR_PSW_C = 0xD7;

  // Other values, not used in this emu:
  /*
  const uint8_t IP = 0xB8; // Interrupt priority control (1 byte).
  const uint8_t IE = 0xA8; // Interrupt enable control (1 byte).
  const uint8_t TMOD = 0x89; // Timer/counter mode control (1 byte).
  const uint8_t TCON = 0x88; // Timer/counter control (1 byte).
  const uint8_t T2CON = 0xC8; // Timer/counter 2 control (1 byte).
  const uint8_t T2MOD = 0xC9; // Timer/counter 2 mode control (1 byte).
  const uint8_t TH0 = 0x8C; // Timer/counter 0 high byte (1 byte).
  const uint8_t TL0 = 0x8A; // Timer/counter 0 low byte (1 byte).
  const uint8_t TH1 = 0x8D; // Timer/counter 1 high byte (1 byte).
  const uint8_t TL1 = 0x8B; // Timer/counter 1 low byte (1 byte).
  const uint8_t TH2 = 0xCD; // Timer/counter 2 high byte (1 byte).
  const uint8_t TL2 = 0xCC; // Timer/counter 2 low byte (1 byte).
  const uint8_t RCAP2H = 0xCB; // T/C 2 capture register high (1 byte).
  const uint8_t RCAP2L = 0xCA; // T/C 2 capture register low (1 byte).
  const uint8_t PCON = 0x87; // Power control (1 byte).
  const uint8_t SCON = 0x98; // Serial control (1 byte).
  const uint8_t SBUF = 0x99; // Serial data (1 byte).
  */

  const uint8_t R0 = 0;  // General purpose registers (1 byte each).
  const uint8_t R1 = 1;  // Actually 4 sets of there, from 0x00 to 0x1F.
  const uint8_t R2 = 2;  // These values might be treated as offsets inside
  const uint8_t R3 = 3;  // the set.
  const uint8_t R4 = 4;
  const uint8_t R5 = 5;
  const uint8_t R6 = 6;
  const uint8_t R7 = 7;

  emu8051();
  ~emu8051();

  // Enable or disable updating the parity flag on writes to A register.
  // BUG: An direct IRAM write to A register won't update parity anyway.
  // Default: enabled
  void option_update_parity_flag(bool enabled);

  // The s51 simulator from ucsim package has the carry flag implemented in a
  // weird way for the DA instruction (i.e. it's never cleared, and set on
  // in too many cases vs what other documentation says).
  // This option allows to turn on s51 compatibility mode for the DA
  // instruction (opcode 0xD4).
  // Default: disabled
  void option_DA_s51_compatibility(bool enabled);

  // Same story, but with SUBB instruction (though here I'm less certain who
  // actually got it right).
  // Default: disabled
  void option_SUBB_s51_compatibility(bool enabled);

  // Note: Since regs are memory mapped in IRAM, these must be used to set
  // registers too (with the exception of PC register).
  bool mem_write(mem_type_t mem_type, uint32_t addr, const void *data, uint32_t size);
  bool mem_read(mem_type_t mem_type, uint32_t addr, void *output, uint32_t size);

  // Set to nullptr to unregister.
  void sfr_register_handler(uint32_t addr, sfr_handler handler);

  // Returns byte address, and bit in the byte for ADDR_BIT addressing.
  std::pair<uint8_t, uint8_t> convert_bit_address(uint32_t addr);

  void pc_set(uint16_t pc);
  uint16_t pc_get() const;

  // These are just shortcuts to some SFRs.
  uint8_t a_get();
  void a_set(uint8_t value);
  void a_update_parity();

  uint8_t b_get();
  void b_set(uint8_t value);

  uint8_t r_get(uint8_t index);
  void r_set(uint8_t index, uint8_t value);

  uint16_t dptr_get();
  void dptr_set(uint16_t value);

  uint8_t psw_get();
  void psw_set(uint8_t value);

  // These are PSW flags, so possible values are 0 or 1.
  uint8_t sfrflag_get_helper(uint8_t bitaddr);
  void sfrflag_set_helper(uint8_t bitaddr, uint8_t value);

  uint8_t cflag_get();  // Carry.
  void cflag_set(uint8_t value);

  uint8_t pflag_get();  // Parity.
  void pflag_set(uint8_t value);

  uint8_t oflag_get();  // Overflow.
  void oflag_set(uint8_t value);

  uint8_t aflag_get();  // Auxiliary overflow.
  void aflag_set(uint8_t value);

  // Use 0 for infinite.
  // This function returns after instruction_count instructions executed or
  // if an event that might require outside processing happens (this is true
  // even if 0 is used as the argument).
  // Returning true denotes that all instruction_count instructions got
  // executed. False is returned otherwise.
  bool execute(uint32_t instruction_count);

 private:
  // IRAM is quite funny in 8051, since it's split into two parts.
  // The lower 128 bytes are pretty normal.
  // The upper 128 bytes behave either as memory-mapped IO if accessed directly,
  // or as normal RAM if accessed indirectly.
  // This emulator by default handles the special registers just as separate RAM
  // cells, however this behavior can be changed by registering handlers.
  std::array<uint8_t, 0x100> iram_;
  std::array<uint8_t, 0x80> iram_sfr_memory_; // Top part.
  std::array<sfr_handler, 0x80> iram_sfr_handlers_;

  // External RAM and Program memory.
  std::array<uint8_t, 0x10000> xram_;
  std::array<uint8_t, 0x10000> pmem_;

  // Option flags.
  bool parity_flag_enabled_{true};
  bool compatibility_DA_s51_enabled_{false};
  bool compatibility_SUBB_s51_enabled_{false};

  uint16_t pc_{};

  bool verify_address(mem_type_t mem_type,
      address_type_t addr_type, uint64_t addr) const;

  // Even though these functions have the _byte suffix, they can be used to
  // address individual bits in case the ADDR_BIT type is used. The bit address
  // convention is the typical 8051 one (see convert_bit_address function).
  bool memctrl_write_byte(
      mem_type_t mem_type, address_type_t addr_type,
      uint32_t addr, uint8_t value);

  bool memctrl_read_byte(
      mem_type_t mem_type, address_type_t addr_type,
      uint32_t addr, uint8_t *value);

  bool iram_write_byte(address_type_t addr_type, uint32_t addr, uint8_t value);
  bool iram_read_byte(address_type_t addr_type, uint32_t addr, uint8_t *value);

  bool sfr_write_byte(address_type_t addr_type, uint32_t addr, uint8_t value);
  bool sfr_read_byte(address_type_t addr_type, uint32_t addr, uint8_t *value);

  bool xram_write_byte(uint32_t addr, uint8_t value);
  bool xram_read_byte(uint32_t addr, uint8_t *value);

  bool pmem_write_byte(uint32_t addr, uint8_t value);
  bool pmem_read_byte(uint32_t addr, uint8_t *value);

  // Returns false on events that might have to be processed outside of the
  // emulator (e.g. an sfr_handler returns false).
  bool execute_single_instruction();

  uint8_t get_byte_at_pc_and_increment();

  // This function might change pc register.
  emu8051opcodes::actual_arg_t get_actual_arg(
      uint8_t opcode, emu8051opcodes::arg_t& arg_type);

  uint16_t eval_arg(emu8051opcodes::actual_arg_t& arg);
  void assign_arg(emu8051opcodes::actual_arg_t& arg, uint16_t value);

  void pc_set_relative(uint8_t value);

  uint8_t stack_pop8();
  uint16_t stack_pop16();

  void stack_push8(uint8_t value);
  void stack_push16(uint16_t value);
};



