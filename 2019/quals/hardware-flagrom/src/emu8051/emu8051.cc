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
#include <algorithm>
#include <utility>
#include "emu8051.h"

using namespace emu8051opcodes;

emu8051::emu8051() {
  iram_.fill(0);
  iram_sfr_memory_.fill(0);
  iram_sfr_handlers_.fill(nullptr);

  xram_.fill(0);
  pmem_.fill(0);
}

emu8051::~emu8051() {
}

void emu8051::option_update_parity_flag(bool enabled) {
  parity_flag_enabled_ = enabled;
}

void emu8051::option_DA_s51_compatibility(bool enabled) {
  compatibility_DA_s51_enabled_ = enabled;
}

void emu8051::option_SUBB_s51_compatibility(bool enabled) {
  compatibility_SUBB_s51_enabled_ = enabled;
}

bool emu8051::verify_address(mem_type_t mem_type,
    address_type_t addr_type, uint64_t addr) const {

  if (addr_type == address_type_t::ADDR_BIT && (
          mem_type == mem_type_t::XRAM ||
          mem_type == mem_type_t::PMEM)) {
    abort(); // Should never happen.
  }

  switch (mem_type) {
    case mem_type_t::IRAM_DIRECT:
    case mem_type_t::IRAM_INDIRECT:
      if (addr >= 0x100) {
        return false;
      }
      break;

    case mem_type_t::XRAM:
    case mem_type_t::PMEM:
      if (addr >= 0x10000) {
        return false;
      }
      break;

    default:
      abort();  // Should never happen.
  }
  return true;
}

bool emu8051::memctrl_write_byte(
    mem_type_t mem_type, address_type_t addr_type,
    uint32_t addr, uint8_t value) {
  if (!verify_address(mem_type, addr_type, addr)) {
    // Must never happen so deep into the emulator.
    abort();
  }

  switch (mem_type) {
    case mem_type_t::IRAM_DIRECT:
      // Note: This check actually works for both address types.
      if (addr < 0x80) {
        return iram_write_byte(addr_type, addr , value);
      } else {
        return sfr_write_byte(addr_type, addr, value);
      }

    case mem_type_t::IRAM_INDIRECT:
      return iram_write_byte(address_type_t::ADDR_BYTE, addr, value);

    case mem_type_t::XRAM:
      return xram_write_byte(addr, value);

    case mem_type_t::PMEM:
      return pmem_write_byte(addr, value);
  }

  // Should never happen.
  abort();
}

bool emu8051::memctrl_read_byte(
    mem_type_t mem_type, address_type_t addr_type,
    uint32_t addr, uint8_t *value) {
  if (!verify_address(mem_type, addr_type, addr)) {
    // Must never happen so deep into the emulator.
    abort();
  }

  switch (mem_type) {
    case mem_type_t::IRAM_DIRECT:
      // Note: This check actually works for both address types.
      if (addr < 0x80) {
        return iram_read_byte(addr_type, addr, value);
      } else {
        return sfr_read_byte(addr_type, addr, value);
      }

    case mem_type_t::IRAM_INDIRECT:
      return iram_read_byte(address_type_t::ADDR_BYTE, addr, value);

    case mem_type_t::XRAM:
      return xram_read_byte(addr, value);

    case mem_type_t::PMEM:
      return pmem_read_byte(addr, value);
  }

  // Should never happen.
  abort();
}

bool emu8051::mem_write(
    mem_type_t mem_type, uint32_t addr, const void *data, uint32_t size) {
  if (size == 0) {
    return true;
  }

  const uint64_t last_addr =
      static_cast<uint64_t>(addr) + static_cast<uint64_t>(size) - 1;
  if (last_addr >= 0x10000) {  // Early sanity check.
    return false;
  }

  if (!verify_address(mem_type, address_type_t::ADDR_BYTE, addr) ||
      !verify_address(mem_type, address_type_t::ADDR_BYTE, last_addr)) {
    return false;
  }

  const uint8_t *const data_bytes = (const uint8_t*)data;

  for (uint32_t i = addr, j = 0;
       i <= static_cast<uint32_t>(last_addr); i++, j++) {
    if (!memctrl_write_byte(mem_type, address_type_t::ADDR_BYTE, i, data_bytes[j])) {
      return false;
    }
  }

  return true;
}

bool emu8051::mem_read(
    mem_type_t mem_type, uint32_t addr, void *output, uint32_t size) {
  if (size == 0) {
    return true;
  }

  uint64_t last_addr = static_cast<uint64_t>(addr) + static_cast<uint64_t>(size) - 1;
  if (last_addr >= 0x10000) {  // Early sanity check.
    return false;
  }

  if (!verify_address(mem_type, address_type_t::ADDR_BYTE, addr) ||
      !verify_address(mem_type, address_type_t::ADDR_BYTE, last_addr)) {
    return false;
  }

  uint8_t *output_bytes = (uint8_t*)output;

  for (uint32_t i = addr, j = 0;
       i <= static_cast<uint32_t>(last_addr);
       i++, j++) {
    if (!memctrl_read_byte(mem_type, address_type_t::ADDR_BYTE, i, &output_bytes[j])) {
      return false;
    }
  }

  return true;
}

bool emu8051::iram_write_byte(address_type_t addr_type, uint32_t addr, uint8_t value) {
  if (addr_type == address_type_t::ADDR_BYTE) {
    iram_.at(addr) = value;
    return true;
  }

  // addr_type == address_type_t::ADDR_BIT

  // In address_type_t::ADDR_BIT mode value must be either 0 or 1.
  if (value > 1) {
    abort();
  }

  auto [addr_byte, addr_bit] = convert_bit_address(addr);
  uint8_t iram_value = iram_.at(addr_byte);

  iram_value &= ~(1 << addr_bit);

  if (value) {
    iram_value |= 1 << addr_bit;
  }

  iram_.at(addr_byte) = iram_value;

  return true;
}

bool emu8051::iram_read_byte(address_type_t addr_type, uint32_t addr, uint8_t *value) {
  if (addr_type == address_type_t::ADDR_BYTE) {
    *value = iram_.at(addr);
    return true;
  }

  // addr_type == address_type_t::ADDR_BIT
  auto [addr_byte, addr_bit] = convert_bit_address(addr);
  uint8_t iram_value = iram_.at(addr_byte);
  *value = (iram_value >> addr_bit) & 1;

  return true;
}

bool emu8051::sfr_write_byte(address_type_t addr_type, uint32_t addr, uint8_t value) {
  if (addr < 0x80 || addr >= 0x100) {
    abort();
  }

  if (addr_type == address_type_t::ADDR_BIT && value > 1) {
    // In address_type_t::ADDR_BIT mode value must be either 0 or 1.
    abort();
  }

  if (addr_type == address_type_t::ADDR_BYTE) {
    const uint8_t index = addr - 0x80;
    sfr_handler handler = iram_sfr_handlers_.at(index);
    if (handler != nullptr) {
      return handler(this, access_type_t::WRITE, address_type_t::ADDR_BYTE, addr, &value);
    }
    iram_sfr_memory_.at(index) = value;
    return true;
  }

  // addr_type == address_type_t::ADDR_BIT
  auto [addr_byte, addr_bit] = convert_bit_address(addr);
  const uint8_t index = addr_byte - 0x80;
  sfr_handler handler = iram_sfr_handlers_.at(index);

  if (handler != nullptr) {
    return handler(this, access_type_t::WRITE, address_type_t::ADDR_BIT, addr, &value);
  }

  uint8_t iram_sfr_value = iram_sfr_memory_.at(index);

  iram_sfr_value &= ~(1 << addr_bit);

  if (value) {
    iram_sfr_value |= 1 << addr_bit;
  }
  iram_sfr_memory_.at(index) = iram_sfr_value;
  return true;
}

bool emu8051::sfr_read_byte(address_type_t addr_type, uint32_t addr, uint8_t *value) {
  if (addr < 0x80 || addr >= 0x100) {
    abort();
  }

  // TODO: So here's a magic question. Should a direct write to SFR 0xE0 (known
  // as the A register) actually recalculate PSW.Parity?
  // If yes, move the a_set's a_update_parity() call somewhere here.

  if (addr_type == address_type_t::ADDR_BYTE) {
    const uint8_t index = addr - 0x80;
    sfr_handler handler = iram_sfr_handlers_.at(index);
    if (handler != nullptr) {
      return handler(this, access_type_t::READ, address_type_t::ADDR_BYTE, addr, value);
    }
    *value = iram_sfr_memory_.at(index);
    return true;
  }

  // addr_type == address_type_t::ADDR_BIT
  auto [addr_byte, addr_bit] = convert_bit_address(addr);
  const uint8_t index = addr_byte - 0x80;
  sfr_handler handler = iram_sfr_handlers_.at(index);

  if (handler != nullptr) {
    return handler(this, access_type_t::READ, address_type_t::ADDR_BIT, addr, value);
  }

  *value = (iram_sfr_memory_.at(index) >> addr_bit) & 1;
  return true;
}

bool emu8051::xram_write_byte(uint32_t addr, uint8_t value) {
  xram_.at(addr) = value;
  return true;
}

bool emu8051::xram_read_byte(uint32_t addr, uint8_t *value) {
  *value = xram_.at(addr);
  return true;
}


bool emu8051::pmem_write_byte(uint32_t addr, uint8_t value) {
  pmem_.at(addr) = value;
  return true;
}

bool emu8051::pmem_read_byte(uint32_t addr, uint8_t *value) {
  *value = pmem_.at(addr);
  return true;
}

void emu8051::sfr_register_handler(uint32_t addr, sfr_handler handler) {
  if (addr < 0x80 || addr >= 0x100) {
    abort();
  }

  uint8_t index = addr - 0x80;
  iram_sfr_handlers_.at(index) = handler;
}

void emu8051::pc_set(uint16_t pc) {
  pc_ = pc;
}

uint16_t emu8051::pc_get() const {
  return pc_;
}

bool emu8051::execute(uint32_t instruction_count) {
  const bool infinite = (instruction_count == 0);

  for (uint32_t executed_count = 0;
       infinite || executed_count < instruction_count;
       executed_count++) {
    if (!execute_single_instruction()) {
      return false;
    }
  }

  return true;
}

uint8_t emu8051::psw_get() {
  uint8_t value = 0;
  sfr_read_byte(address_type_t::ADDR_BYTE, PSW, &value);
  if (!parity_flag_enabled_) {
    value &= 0xfe;
  }
  return value;
}

void emu8051::psw_set(uint8_t value) {
  if (!parity_flag_enabled_) {
    value &= 0xfe;
  }
  sfr_write_byte(address_type_t::ADDR_BYTE, PSW, value);
}

uint8_t emu8051::sfrflag_get_helper(uint8_t bitaddr) {
  uint8_t value = 0;
  sfr_read_byte(address_type_t::ADDR_BIT, bitaddr, &value);
  return value;
}

void emu8051::sfrflag_set_helper(uint8_t bitaddr, uint8_t value) {
  if (value > 1) {
    abort();
  }

  sfr_write_byte(address_type_t::ADDR_BIT, bitaddr, value);
}

uint8_t emu8051::cflag_get() {
  return sfrflag_get_helper(BITADDR_PSW_C);
}

void emu8051::cflag_set(uint8_t value) {
  sfrflag_set_helper(BITADDR_PSW_C, value);
}

uint8_t emu8051::pflag_get() {
  return sfrflag_get_helper(BITADDR_PSW_P);
}

void emu8051::pflag_set(uint8_t value) {
  sfrflag_set_helper(BITADDR_PSW_P, value);
}

uint8_t emu8051::oflag_get() {
  return sfrflag_get_helper(BITADDR_PSW_OV);
}

void emu8051::oflag_set(uint8_t value) {
  sfrflag_set_helper(BITADDR_PSW_OV, value);
}

uint8_t emu8051::aflag_get() {
  return sfrflag_get_helper(BITADDR_PSW_AC);
}

void emu8051::aflag_set(uint8_t value) {
  sfrflag_set_helper(BITADDR_PSW_AC, value);
}

uint8_t emu8051::a_get() {
  uint8_t value = 0;
  sfr_read_byte(address_type_t::ADDR_BYTE, A, &value);
  return value;
}

void emu8051::a_update_parity() {
  if (!parity_flag_enabled_) {
    return;
  }

  uint8_t a = a_get();

  // Update parity flag.
  uint8_t p = 1;
  for (uint8_t i = 0; i < 8; i++) {
    p ^= (a >> i) & 1;
  }
  pflag_set(p);
}

void emu8051::a_set(uint8_t value) {
  sfr_write_byte(address_type_t::ADDR_BYTE, A, value);
  a_update_parity();
}

uint8_t emu8051::b_get() {
  uint8_t value = 0;
  sfr_read_byte(address_type_t::ADDR_BYTE, B, &value);
  return value;
}

void emu8051::b_set(uint8_t value) {
  sfr_write_byte(address_type_t::ADDR_BYTE, B, value);
}

uint8_t emu8051::r_get(uint8_t index) {
  if(index >= 8) {
    abort();
  }

  const uint8_t bank = (psw_get() >> PSW_RS) & 3;

  uint8_t value = 0;
  iram_read_byte(address_type_t::ADDR_BYTE, bank * 8 + index, &value);
  return value;
}

void emu8051::r_set(uint8_t index, uint8_t value) {
  if(index >= 8) {
    abort();
  }

  const uint8_t bank = (psw_get() >> PSW_RS) & 3;

  iram_write_byte(address_type_t::ADDR_BYTE, bank * 8 + index, value);
}

uint16_t emu8051::dptr_get() {
  uint8_t dpl = 0;
  uint8_t dph = 0;
  sfr_read_byte(address_type_t::ADDR_BYTE, DPL, &dpl);
  sfr_read_byte(address_type_t::ADDR_BYTE, DPH, &dph);
  const uint16_t dptr = (static_cast<uint16_t>(dph) << 8) | dpl;
  return dptr;
}

void emu8051::dptr_set(uint16_t value) {
  sfr_write_byte(address_type_t::ADDR_BYTE, DPL, value & 0xff);
  sfr_write_byte(address_type_t::ADDR_BYTE, DPH, value >> 8);
}

uint16_t emu8051::eval_arg(emu8051opcodes::actual_arg_t& arg) {
  //uint16_t value16;
  uint8_t value8 = 0;

  switch(arg.type) {
    case arg_t::ARG_NONE:
      abort();  // Should never be called.

    case arg_t::ARG_A:
      return a_get();

    case arg_t::ARG_B:
      return b_get();

    case arg_t::ARG_R:
      return r_get(arg.param8);

    case arg_t::ARG_R0_INDIRECT_IRAM:
      memctrl_read_byte(mem_type_t::IRAM_INDIRECT, address_type_t::ADDR_BYTE, r_get(0), &value8);
      return value8;

    case arg_t::ARG_R1_INDIRECT_IRAM:
      memctrl_read_byte(mem_type_t::IRAM_INDIRECT, address_type_t::ADDR_BYTE, r_get(1), &value8);
      return value8;

    case arg_t::ARG_R0_INDIRECT_XRAM:
      memctrl_read_byte(mem_type_t::XRAM, address_type_t::ADDR_BYTE, r_get(0), &value8);
      return value8;

    case arg_t::ARG_R1_INDIRECT_XRAM:
      memctrl_read_byte(mem_type_t::XRAM, address_type_t::ADDR_BYTE, r_get(1), &value8);
      return value8;

    case arg_t::ARG_DIRECT_IRAM:
      memctrl_read_byte(mem_type_t::IRAM_DIRECT, address_type_t::ADDR_BYTE, arg.param8, &value8);
      return value8;

    case arg_t::ARG_IMM8:
      return arg.param8;

    case arg_t::ARG_IMM11:
      return arg.param16;

    case arg_t::ARG_IMM16:
      return arg.param16;

    case arg_t::ARG_REL8:
      return arg.param8;

    case arg_t::ARG_C:
      return cflag_get();

    case arg_t::ARG_BIT:
      memctrl_read_byte(mem_type_t::IRAM_DIRECT, address_type_t::ADDR_BIT, arg.param8, &value8);
      return value8;

    case arg_t::ARG_NEG_BIT:
      memctrl_read_byte(mem_type_t::IRAM_DIRECT, address_type_t::ADDR_BIT, arg.param8, &value8);
      return value8 ^ 1;

    case arg_t::ARG_DPTR:
      return dptr_get();

    case arg_t::ARG_DPTR_INDIRECT_XRAM:
      memctrl_read_byte(mem_type_t::XRAM, address_type_t::ADDR_BYTE, dptr_get(), &value8);
      return value8;

    case arg_t::ARG_A_DPTR:
      return (a_get() + dptr_get()) & 0xffff;

    case arg_t::ARG_A_PC_INDIRECT_PMEM:
      memctrl_read_byte(mem_type_t::PMEM, address_type_t::ADDR_BYTE, (a_get() + pc_get()) & 0xffff, &value8);
      return value8;

    case arg_t::ARG_A_DPTR_INDIRECT_PMEM:
      memctrl_read_byte(mem_type_t::PMEM, address_type_t::ADDR_BYTE, (a_get() + dptr_get()) & 0xffff, &value8);
      return value8;
  }

  abort();
}

void emu8051::assign_arg(emu8051opcodes::actual_arg_t& arg, uint16_t value) {
  const uint8_t value8 = static_cast<uint8_t>(value);
  switch(arg.type) {
    case arg_t::ARG_A:
      a_set(value8);
      break;

    case arg_t::ARG_B:
      b_set(value8);
      break;

    case arg_t::ARG_R:
      r_set(arg.param8, value8);
      break;

    case arg_t::ARG_R0_INDIRECT_IRAM:
      memctrl_write_byte(mem_type_t::IRAM_INDIRECT, address_type_t::ADDR_BYTE, r_get(0), value8);
      break;

    case arg_t::ARG_R1_INDIRECT_IRAM:
      memctrl_write_byte(mem_type_t::IRAM_INDIRECT, address_type_t::ADDR_BYTE, r_get(1), value8);
      break;

    case arg_t::ARG_R0_INDIRECT_XRAM:
      memctrl_write_byte(mem_type_t::XRAM, address_type_t::ADDR_BYTE, r_get(0), value8);
      break;

    case arg_t::ARG_R1_INDIRECT_XRAM:
      memctrl_write_byte(mem_type_t::XRAM, address_type_t::ADDR_BYTE, r_get(1), value8);
      break;

    case arg_t::ARG_DIRECT_IRAM:
      memctrl_write_byte(mem_type_t::IRAM_DIRECT, address_type_t::ADDR_BYTE, arg.param8, value8);
      break;

    case arg_t::ARG_C:
      cflag_set(value8);
      break;

    case arg_t::ARG_BIT:
      memctrl_write_byte(mem_type_t::IRAM_DIRECT, address_type_t::ADDR_BIT, arg.param8, value8);
      break;

    case arg_t::ARG_DPTR:
      dptr_set(value);
      break;

    case arg_t::ARG_DPTR_INDIRECT_XRAM:
      memctrl_write_byte(mem_type_t::XRAM, address_type_t::ADDR_BYTE, dptr_get(), value8);
      break;

    case arg_t::ARG_NONE:
    case arg_t::ARG_IMM11:
    case arg_t::ARG_IMM8:
    case arg_t::ARG_IMM16:
    case arg_t::ARG_REL8:
    case arg_t::ARG_A_DPTR:
    case arg_t::ARG_NEG_BIT:
    case arg_t::ARG_A_PC_INDIRECT_PMEM:
    case arg_t::ARG_A_DPTR_INDIRECT_PMEM:
      abort();  // Should never be called (there are no instructions like this).
  }
}

void emu8051::pc_set_relative(uint8_t value) {
  const uint16_t value_sign_extended = value | (value >= 0x80 ? 0xff00 : 0);
  pc_ += value_sign_extended;  // Overflow is expected here.
}

uint8_t emu8051::stack_pop8() {
  uint8_t sp;
  sfr_read_byte(address_type_t::ADDR_BYTE, SP, &sp);

  uint8_t value;
  iram_read_byte(address_type_t::ADDR_BYTE, sp, &value);

  sp -= 1;
  sfr_write_byte(address_type_t::ADDR_BYTE, SP, sp);

  return value;
}

uint16_t emu8051::stack_pop16() {
  uint16_t value;
  value = static_cast<uint16_t>(stack_pop8()) << 8;
  value |= stack_pop8();
  return value;
}

void emu8051::stack_push8(uint8_t value) {
  uint8_t sp;
  sfr_read_byte(address_type_t::ADDR_BYTE, SP, &sp);
  sp += 1;
  sfr_write_byte(address_type_t::ADDR_BYTE, SP, sp);

  iram_write_byte(address_type_t::ADDR_BYTE, sp, value);
}

void emu8051::stack_push16(uint16_t value) {
  stack_push8(value & 0xff);
  stack_push8(value >> 8);
}

bool emu8051::execute_single_instruction() {
  const uint16_t instruction_pc = pc_;
  (void)instruction_pc;  // Sometimes used.

  const uint8_t opcode = get_byte_at_pc_and_increment();
  instruction_decode_table_t decoded_ins = instruction_decode_table[opcode];

  // Decode the arguments. This might increase pc registers in some cases.
  emu8051opcodes::actual_arg_t actual_arg[3];
  actual_arg[0] = get_actual_arg(opcode, decoded_ins.arg1);
  actual_arg[1] = get_actual_arg(opcode, decoded_ins.arg2);
  actual_arg[2] = get_actual_arg(opcode, decoded_ins.arg3);

  if (opcode == 0x85) {
    // MOV iram addr, iram addr actually has these arguments in reverse.
    std::swap(actual_arg[0], actual_arg[1]);
  }

  // There are only 44 instructions, so I guess they can just be here.
  // Information source:
  // - https://www.win.tue.nl/~aeb/comp/8051/set8051.html
  // - http://www.keil.com/support/man/docs/is51/is51_instructions.htm
  // Both have minor typos here and there, so take care.
  switch (decoded_ins.instruction) {
    case instruction_t::INS_UNDEFINED:
      // A5 undefined instruction.
      // TODO(gynvael): Perhaps add support for various implementations of A5.
      break;

    case instruction_t::INS_ACALL: {
      uint16_t pc = pc_get();
      stack_push16(pc);
      pc &= 0xf800;
      pc |= eval_arg(actual_arg[0]);
      pc_set(pc);
    } break;

    case instruction_t::INS_ADD:
    case instruction_t::INS_ADDC: {
      uint8_t op0 = eval_arg(actual_arg[0]);
      uint8_t op1 = eval_arg(actual_arg[1]);
      uint8_t opc = decoded_ins.instruction == instruction_t::INS_ADDC ? cflag_get() : 0;
      uint16_t res = static_cast<uint16_t>(op0) +
                     static_cast<uint16_t>(op1) + opc;

      assign_arg(actual_arg[0], static_cast<uint8_t>(res));

      cflag_set(res > 255);
      aflag_set((op0 & 0xf) + (op1 & 0xf) + opc > 15);

      // Signed operations.
      int8_t sop0 = static_cast<int8_t>(op0);
      int8_t sop1 = static_cast<int8_t>(op1);
      int16_t sres = static_cast<int16_t>(sop0) +
                     static_cast<int16_t>(sop1) + opc;
      oflag_set(sres < -128 || sres > 127);
    } break;

    case instruction_t::INS_AJMP: {
      uint16_t pc = pc_get();
      pc &= 0xf800;
      pc |= eval_arg(actual_arg[0]);
      pc_set(pc);
    } break;

    case instruction_t::INS_ANL:
      assign_arg(actual_arg[0], eval_arg(actual_arg[0]) & eval_arg(actual_arg[1]));
      break;

    case instruction_t::INS_CJNE: {
      uint8_t op0 = eval_arg(actual_arg[0]);
      uint8_t op1 = eval_arg(actual_arg[1]);
      if (op0 != op1) {
        pc_set_relative(eval_arg(actual_arg[2]));
      }
      cflag_set(op0 < op1);
    } break;

    case instruction_t::INS_CLR:
      assign_arg(actual_arg[0], 0);
      break;

    case instruction_t::INS_CPL:  // NOT
      // TODO: This --> If the operand refers to a bit of an output Port, the
      // value that will be complemented is based on the last value written to
      // that bit, not the last value read from it.
      if (actual_arg[0].type == arg_t::ARG_A) {
        // Byte.
        assign_arg(actual_arg[0], eval_arg(actual_arg[0]) ^ 0xff);
      } else {
        // Bit.
       assign_arg(actual_arg[0], eval_arg(actual_arg[0]) ^ 1);
      }
      break;

    case instruction_t::INS_DA: {
      uint16_t a = a_get();
      if ((a & 0xf) > 9 || aflag_get() == 1) {
        a += 6;
      }

      if (((a >> 4) & 0xf) > 9 || cflag_get() == 1) {
        a += 0x60;
      }

      if (compatibility_DA_s51_enabled_) {
        cflag_set(cflag_get() | (a > 0xff));
      } else {
        cflag_set(a > 0x99);
      }

      a_set(a & 0xff);
      } break;

    case instruction_t::INS_DEC:
      assign_arg(actual_arg[0], (eval_arg(actual_arg[0]) - 1) & 0xff);
      break;

    case instruction_t::INS_DIV: {
      cflag_set(0);  // Always cleared.

      uint8_t op0 = eval_arg(actual_arg[0]);  // A
      uint8_t op1 = eval_arg(actual_arg[1]);  // B
      if (op1 == 0) {
        // TODO: Figure out if A or B is actually changed.
        oflag_set(1);
        break;
      }

      assign_arg(actual_arg[0], op0 / op1);
      assign_arg(actual_arg[1], op0 % op1);
      oflag_set(0);
    } break;

    case instruction_t::INS_DJNZ: {
      uint8_t op = eval_arg(actual_arg[0]);
      op--;
      assign_arg(actual_arg[0], op);

      if (op != 0) {
        pc_set_relative(eval_arg(actual_arg[1]));
      }
    } break;

    case instruction_t::INS_INC:
      if (actual_arg[0].type == arg_t::ARG_DPTR) {
        assign_arg(actual_arg[0], (eval_arg(actual_arg[0]) + 1) & 0xffff);
      } else {
        assign_arg(actual_arg[0], (eval_arg(actual_arg[0]) + 1) & 0xff);
      }
      break;

    case instruction_t::INS_JB:
      if (eval_arg(actual_arg[0]) == 1) {
        pc_set_relative(eval_arg(actual_arg[1]));
      }
      break;

    case instruction_t::INS_JBC:
      if (eval_arg(actual_arg[0]) == 1) {
        assign_arg(actual_arg[0], 0);
        pc_set_relative(eval_arg(actual_arg[1]));
      }
      break;

    case instruction_t::INS_JC:
      if (cflag_get() == 1) {
        pc_set_relative(eval_arg(actual_arg[0]));
      }
      break;

    case instruction_t::INS_JMP:
      pc_set(eval_arg(actual_arg[0]));
      break;

    case instruction_t::INS_JNB:
      if (eval_arg(actual_arg[0]) == 0) {
        pc_set_relative(eval_arg(actual_arg[1]));
      }
      break;

    case instruction_t::INS_JNC:
      if (cflag_get() == 0) {
        pc_set_relative(eval_arg(actual_arg[0]));
      }
      break;

    case instruction_t::INS_JNZ:
      if (a_get() != 0) {
        pc_set_relative(eval_arg(actual_arg[0]));
      }
      break;

    case instruction_t::INS_JZ:
      if (a_get() == 0) {
        pc_set_relative(eval_arg(actual_arg[0]));
      }
      break;

    case instruction_t::INS_LCALL:
      stack_push16(pc_get());
      pc_set(eval_arg(actual_arg[0]));
      break;

    case instruction_t::INS_LJMP:
      pc_set(eval_arg(actual_arg[0]));
      break;

    case instruction_t::INS_MOV:
    case instruction_t::INS_MOVC:
    case instruction_t::INS_MOVX:
      // Technically MOVX uses P0 and P2 to control external RAM chips, but
      // we don't implement that.
      assign_arg(actual_arg[0], eval_arg(actual_arg[1]));
      break;

    case instruction_t::INS_MUL: {
      cflag_set(0);  // Always cleared.

      uint8_t op0 = eval_arg(actual_arg[0]);  // A
      uint8_t op1 = eval_arg(actual_arg[1]);  // B
      uint16_t res = static_cast<uint8_t>(op0) * static_cast<uint8_t>(op1);

      assign_arg(actual_arg[0], res & 0xff);
      assign_arg(actual_arg[1], res >> 8);

      oflag_set(res > 255);
    } break;

    case instruction_t::INS_NOP:
      // Do nothing.
      break;

    case instruction_t::INS_ORL:
      assign_arg(actual_arg[0], eval_arg(actual_arg[0]) | eval_arg(actual_arg[1]));
      break;

    case instruction_t::INS_POP:
      assign_arg(actual_arg[0], stack_pop8());
      break;

    case instruction_t::INS_PUSH:
      stack_push8(eval_arg(actual_arg[0]));
      break;

    case instruction_t::INS_RET:
      pc_set(stack_pop16());
      break;

    case instruction_t::INS_RETI:
      // TODO: RETI first enables interrupts of equal and lower priorities to
      // the interrupt that is terminating.
      pc_set(stack_pop16());
      break;

    case instruction_t::INS_RL: {
      uint8_t a = a_get();
      a_set(((a << 1) | (a >> 7)) & 0xff);
    } break;

    case instruction_t::INS_RLC: {
      uint8_t a = a_get();
      uint8_t c = cflag_get();
      cflag_set(a >> 7);
      a_set(((a << 1) | c) & 0xff);
    } break;

    case instruction_t::INS_RR: {
      uint8_t a = a_get();
      a_set(((a >> 1) | (a << 7)) & 0xff);
    } break;

    case instruction_t::INS_RRC: {
      uint8_t a = a_get();
      uint8_t c = cflag_get();
      cflag_set(a & 1);
      a_set(((a >> 1) | (c << 7)));
    } break;

    case instruction_t::INS_SETB:
      assign_arg(actual_arg[0], 1);
      break;

    case instruction_t::INS_SJMP:
      pc_set_relative(eval_arg(actual_arg[0]));
      break;

    case instruction_t::INS_SUBB: {
      uint8_t op0 = eval_arg(actual_arg[0]);
      uint8_t c = cflag_get();
      uint16_t op1 = eval_arg(actual_arg[1]);
      uint16_t op1c = op1 + c;
      uint16_t res = static_cast<uint16_t>(op0) - op1c;

      cflag_set(op1c > op0);

      // I'm not sure this auxiliary carry flag calculations are OK.
      if (compatibility_SUBB_s51_enabled_) {
        aflag_set(((op1c & 0xf) > (op0 & 0xf)) ||
                  (c && (op1 & 0xf) == 0xf));
      } else {
        aflag_set((op1c & 0xf) > (op0 & 0xf));
      }

      assign_arg(actual_arg[0], res & 0xff);

      int8_t sop0 = static_cast<int8_t>(op0);
      int8_t sop1 = static_cast<int8_t>(op1c);
      int16_t sres = static_cast<int16_t>(sop0) -
                    static_cast<int16_t>(sop1);

      oflag_set(sres < -128 || sres > 127);
    } break;

    case instruction_t::INS_SWAP: {
      uint8_t a = a_get();
      a_set(((a << 4) | (a >> 4)) & 0xff);
    } break;

    case instruction_t::INS_XCH: {
      uint8_t op0 = eval_arg(actual_arg[0]);
      uint8_t op1 = eval_arg(actual_arg[1]);
      assign_arg(actual_arg[1], op0);
      assign_arg(actual_arg[0], op1);
    } break;

    case instruction_t::INS_XCHD:{
      uint8_t op0 = eval_arg(actual_arg[0]);
      uint8_t op1 = eval_arg(actual_arg[1]);
      assign_arg(actual_arg[1], (op1 & 0xf0) | (op0 & 0x0f));
      assign_arg(actual_arg[0], (op0 & 0xf0) | (op1 & 0x0f));
    } break;

    case instruction_t::INS_XRL:
      assign_arg(actual_arg[0], eval_arg(actual_arg[0]) ^ eval_arg(actual_arg[1]));
      break;
  }

  return true;
}

uint8_t emu8051::get_byte_at_pc_and_increment() {
  uint8_t byte;

  if (!memctrl_read_byte(mem_type_t::PMEM, address_type_t::ADDR_BYTE, pc_, &byte)) {
    abort();
  }

  // This might overflow from FFFF to 0000.
  // TODO: If we ever support bank switching, and overflow might need to
  // increment the bank number (XAR).
  pc_++;

  return byte;
}

std::pair<uint8_t, uint8_t> emu8051::convert_bit_address(uint32_t addr) {
  if (addr >= 0x100) {
    abort();
  }

  if (addr < 0x80) {
    return std::make_pair(
        static_cast<uint8_t>(0x20 + addr / 8),
        static_cast<uint8_t>(addr & 7)
    );
  }

  return std::make_pair(
      static_cast<uint8_t>(addr & 0xf8),
      static_cast<uint8_t>(addr & 7)
  );
}

emu8051opcodes::actual_arg_t emu8051::get_actual_arg(
      uint8_t opcode, emu8051opcodes::arg_t& arg_type) {

  emu8051opcodes::actual_arg_t actual;
  actual.type = arg_type;
  actual.param8 = 0xcc;
  actual.param16 = 0xcccc;

  switch (arg_type) {
    case arg_t::ARG_NONE:
    case arg_t::ARG_A:
    case arg_t::ARG_B:
    case arg_t::ARG_R0_INDIRECT_IRAM:
    case arg_t::ARG_R1_INDIRECT_IRAM:
    case arg_t::ARG_R0_INDIRECT_XRAM:
    case arg_t::ARG_R1_INDIRECT_XRAM:
    case arg_t::ARG_C:
    case arg_t::ARG_DPTR:
    case arg_t::ARG_DPTR_INDIRECT_XRAM:
    case arg_t::ARG_A_DPTR:
    case arg_t::ARG_A_PC_INDIRECT_PMEM:
    case arg_t::ARG_A_DPTR_INDIRECT_PMEM:
      break;

    case arg_t::ARG_R:
      actual.param8 = opcode & 7;
      break;

    case arg_t::ARG_DIRECT_IRAM:
    case arg_t::ARG_REL8:
    case arg_t::ARG_IMM8:
    case arg_t::ARG_BIT:
    case arg_t::ARG_NEG_BIT:
      actual.param8 = get_byte_at_pc_and_increment();
      break;

    case arg_t::ARG_IMM11:
      actual.param16 = get_byte_at_pc_and_increment();
      actual.param16 |= static_cast<uint16_t>(opcode >> 5) << 8;
      break;

    case arg_t::ARG_IMM16:  // Surprisingly this is a big-endian machine.
      actual.param16 = static_cast<uint16_t>(get_byte_at_pc_and_increment()) << 8;
      actual.param16 |= get_byte_at_pc_and_increment();
      break;
  }

  return actual;
}
