/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "emu.h"

// BUG: these dont need to be rwx
#define NEW_PAGE() mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, 0, 0)
#define DEL_PAGE(ptr) { \
    munmap((ptr), PAGE_SIZE); \
    (ptr) = NULL; \
}

#define FAULT() \
    emu->faulted = true; \
    return false;

#define FLAG_BIT(offset) ((emu->flags >> offset) & 1)
#define SET_FLAG(offset, value) (emu->flags |= ((value&1) << offset))

char* __attribute__((noinline)) get_flag() {
    char* flag = getenv("FLAG");
    if (!flag) {
        ELOG("no $FLAG set! do you need to hack harder?");
    }
    return flag;
}

emulator_t* new_emulator(program_t* prog) {
    emulator_t* emu = calloc(1, sizeof(emulator_t));

    emu->code_page = NEW_PAGE();
    emu->data_page = NEW_PAGE();
    emu->stack_page = NEW_PAGE();
    emu->arch_bitmap = calloc(1, prog->arch_bitmap_sz);

    emu->flag = get_flag;

    memcpy(emu->code_page, prog->code_bytes, prog->code_sz);
    memcpy(emu->data_page, prog->data_bytes, prog->data_sz);
    memcpy(emu->arch_bitmap, prog->arch_bitmap, prog->arch_bitmap_sz);
    emu->arch_bitmap_sz = prog->arch_bitmap_sz;

    emu->pc = EVA_CODE_BASE;
    emu->sp = EVA_STACK_BASE + (PAGE_SIZE - 0x100);

    return emu;
}

void free_emulator(emulator_t* emu) {
    DEL_PAGE(emu->code_page);
    DEL_PAGE(emu->data_page);
    DEL_PAGE(emu->stack_page);

    free(emu->arch_bitmap);
    emu->arch_bitmap = NULL;

    for (int i = 0; i < emu->chunk_count; i++) {
        free(emu->chunks[i].ptr);
        emu->chunks[i].ptr = NULL;
    }
    emu->chunk_count = 0;

    free(emu);
}

void* eva_to_va(emulator_t* emu, eva_t addr, size_t out_sz) {
    if (addr >= EVA_CODE_BASE && addr + out_sz < EVA_CODE_BASE + PAGE_SIZE) {
        return emu->code_page + (addr - EVA_CODE_BASE);
    }
    else if (addr >= EVA_DATA_BASE && addr + out_sz < EVA_DATA_BASE + PAGE_SIZE) {
        return emu->data_page + (addr - EVA_DATA_BASE);
    }
    else if (addr >= EVA_STACK_BASE && addr + out_sz < EVA_STACK_BASE + PAGE_SIZE) {
        return emu->stack_page + (addr - EVA_STACK_BASE);
    }
    else if (emu->chunk_count > 0) {
        for (int i = 0; i < emu->chunk_count; i++) {
            dynchunk_t* chunk = &emu->chunks[i];
            if (addr >= chunk->eva && addr + out_sz < chunk->eva + DYNCHUNK_SZ) {
                return chunk->ptr + (addr - chunk->eva);
            }
        }
    }

    return NULL;
}

// read out_sz bytes from addr and write them to out
// returns true on good read (ie the addr could be translated and enough bytes were available),
// otherwise false
bool read_bytes_at_eva(emulator_t* emu, eva_t addr, void* out, size_t out_sz) {
    void* ptr = eva_to_va(emu, addr, out_sz);
    if (!ptr) {
        ELOG("invalid eva, can't read: %#x", addr);
        return false;
    }

    memcpy(out, ptr, out_sz);
    return true;
}

bool read_dword_at_eva(emulator_t* emu, eva_t addr, uint32_t* out) {
    return read_bytes_at_eva(emu, addr, out, 4);
}

bool read_word_at_eva(emulator_t* emu, eva_t addr, uint16_t* out) {
    return read_bytes_at_eva(emu, addr, out, 2);
}

bool read_byte_at_eva(emulator_t* emu, eva_t addr, uint8_t* out) {
    return read_bytes_at_eva(emu, addr, out, 1);
}

bool write_bytes_to_eva(emulator_t* emu, eva_t addr, void* data, size_t data_sz) {
    void* ptr = eva_to_va(emu, addr, data_sz);
    if (!ptr) {
        ELOG("invalid eva, can't write: %#x", addr);
        return false;
    }

    memcpy(ptr, data, data_sz);
    return true;
}

bool write_dword_to_eva(emulator_t* emu, eva_t addr, uint32_t data) {
    return write_bytes_to_eva(emu, addr, &data, 4);
}

bool write_word_to_eva(emulator_t* emu, eva_t addr, uint16_t data) {
    return write_bytes_to_eva(emu, addr, &data, 2);
}

bool write_byte_to_eva(emulator_t* emu, eva_t addr, uint8_t data) {
    return write_bytes_to_eva(emu, addr, &data, 1);
}

bool push_byte_to_stack(emulator_t* emu, uint8_t value) {
    emu->sp -= 1;
    return write_byte_to_eva(emu, emu->sp, value);
}

bool push_word_to_stack(emulator_t* emu, uint16_t value) {
    emu->sp -= 2;
    return write_word_to_eva(emu, emu->sp, value);
}

bool push_dword_to_stack(emulator_t* emu, uint32_t value) {
    emu->sp -= 4;
    return write_dword_to_eva(emu, emu->sp, value);
}

bool pop_byte_from_stack(emulator_t* emu, uint8_t* out) {
    if (!read_byte_at_eva(emu, emu->sp, out)) return false;
    emu->sp += 1;
    return true;
}

bool pop_word_from_stack(emulator_t* emu, uint16_t* out) {
    if (!read_word_at_eva(emu, emu->sp, out)) return false;
    emu->sp += 2;
    return true;
}

bool pop_dword_from_stack(emulator_t* emu, uint32_t* out) {
    if (!read_dword_at_eva(emu, emu->sp, out)) return false;
    emu->sp += 4;
    return true;
}

// these two funcs aren't used but are retained in the final binary
// purpose is to help players undersatnd the cpl function
// (and that they need to bypass it)
void privlev_up(emulator_t* emu) {
    DLOG_KEEP("executing as system now");
    emu->cpl = PL_SYS;
}

void privlev_down(emulator_t* emu) {
    DLOG_KEEP("executing as user now");
    emu->cpl = PL_USER;
}

// check if the current privilege level is allowed to execute the syscall
// gets the syscall number from gp reg A
bool can_execute_syscall(emulator_t* emu) {
    uint8_t syscall_num = emu->gp_regs[REG_A];

    switch (syscall_num) {
    case SYS_READ_DWORD:
    case SYS_READ_BYTES:
    case SYS_WRITE:
    case SYS_PRNG_SEED:
    case SYS_PRNG_GET:
    case SYS_FLAG:
        return emu->cpl >= PL_USER;
    case SYS_MMAP:
        return emu->cpl >= PL_SYS;
    }

    ELOG("invalid syscall! %#x", syscall_num);
    return false;
}

// get the architecture bit for the current pc
uint8_t get_arch_for_insn(emulator_t* emu) {
    int bit_offset = (emu->pc - EVA_CODE_BASE);
    int byte_offset = bit_offset / 8;
    bit_offset %= 8;

    return (emu->arch_bitmap[byte_offset] >> bit_offset) & 1;
}

bool do_syscall_read_dword(emulator_t* emu, uint32_t* out) {
    fscanf(stdin, "%u", out);
    fgetc(stdin);
    return true;
}

bool do_syscall_read_bytes(emulator_t* emu, eva_t out, uint8_t sz) {
    bool ret = true;
    size_t off = 0;
    char* buf = calloc(1, sz);

    while (off < sz) {
        buf[off++] = fgetc(stdin);
        if (buf[off - 1] == '\n')  break;
    }
    buf[strcspn(buf, "\n")] = 0;

    if (!write_bytes_to_eva(emu, out, buf, sz)) {
        ret = false;
    }
    free(buf);
    return ret;
}

bool do_syscall_write(emulator_t* emu, eva_t addr, uint8_t sz) {
    void* out = malloc(sz);
    if (!read_bytes_at_eva(emu, addr, out, sz)) {
        free(out);
        FAULT();
    }

    fwrite(out, 1, sz, stdout);
    free(out);
    return true;
}

bool do_syscall_prng_seed(emulator_t* emu, uint32_t seed) {
    srand(seed);
    return true;
}

bool do_syscall_prng_get(emulator_t* emu, uint32_t* out) {
    *out = rand() & 0xffff;
    *out |= (rand() & 0xffff) << 16;

    return true;
}

bool do_syscall_flag(emulator_t* emu) {
    char* flag = emu->flag();
    if (!flag) {
        FAULT();
    }
    fprintf(stdout, "Here, have a flag: %s\n", flag);
    return true;
}

bool do_syscall_mmap(emulator_t* emu, eva_t requested_base, eva_t* base) {
    if (emu->chunk_count == MAX_DYNCHUNKS) return false;

    requested_base &= 0xfffff000;

    if (requested_base == 0) {
        requested_base = 0xa000;
    }

    // make sure we alloc at an unused base
    while (eva_to_va(emu, requested_base, 1)) requested_base += 0x1000;

    // map the new page
    uint8_t chunk_idx = emu->chunk_count++;
    emu->chunks[chunk_idx].ptr = calloc(DYNCHUNK_SZ, 1);
    emu->chunks[chunk_idx].eva = requested_base;

    *base = requested_base;

    return true;
}

void do_cmp(emulator_t* emu, uint32_t val1, uint32_t val2) {
    emu->flags = 0;
    int32_t result = val1 - val2;
    if (result == 0) {
        SET_FLAG(FLAG_Z, 1);
    }
    else if (result < 0) {
        SET_FLAG(FLAG_O, 1);
    }
    if (result == (uint32_t)result) {
        SET_FLAG(FLAG_S, 1);
    }
}

bool execute_stackvm_insn(emulator_t* emu) {
    uint8_t insn_bytes[5];
    bool pc_taint = false;
    if (!read_bytes_at_eva(emu, emu->pc, insn_bytes, 5)) {
        FAULT();
    }

    switch (insn_bytes[0]) {
    case 0x10: {
        DLOG("executing S.LDB");
        if (memcmp(&insn_bytes[2], "\x00\x00\x00", 3) != 0) {
            ELOG("invalid S.LDB");
            FAULT();
        }
        if (!push_byte_to_stack(emu, insn_bytes[1])) {
            FAULT();
        }
        break;
    }
    case 0x20: {
        DLOG("executing S.LDW");
        if (memcmp(&insn_bytes[3], "\x00\x00", 2) != 0) {
            ELOG("invalid S.LDW");
            FAULT();
        }
        void* ptr = &insn_bytes[1];
        if (!push_word_to_stack(emu, *(uint16_t*)ptr)) {
            FAULT();
        }
        break;
    }
    case 0x30: {
        DLOG("executing S.LDD");
        void* ptr = &insn_bytes[1];
        if (!push_dword_to_stack(emu, *(uint32_t*)ptr)) {
            FAULT();
        }
        break;
    }
    case 0x40: {
        DLOG("executing S.LDP");
        void* ptr = &insn_bytes[1];
        eva_t addr = *(eva_t*)ptr;

        uint32_t val;
        if (!read_dword_at_eva(emu, addr, &val)) {
            ELOG("invalid S.LDP, bad addr");
            FAULT();
        }

        if (!push_dword_to_stack(emu, val)) {
            FAULT();
        }
        break;
    }
    case 0x50: {
        DLOG("executing S.POP");
        uint32_t val;
        if (!pop_dword_from_stack(emu, &val)) {
            FAULT();
        }
        break;
    }
    case 0x60: {
        DLOG("executing S.ADD");
        uint32_t val1, val2;
        if (!pop_dword_from_stack(emu, &val1) || !pop_dword_from_stack(emu, &val2)) {
            FAULT();
        }
        if (!push_dword_to_stack(emu, val1 + val2)) {
            FAULT();
        }
        break;
    }
    case 0x61: {
        DLOG("executing S.SUB");
        uint32_t val1, val2;
        if (!pop_dword_from_stack(emu, &val1) || !pop_dword_from_stack(emu, &val2)) {
            FAULT();
        }
        if (!push_dword_to_stack(emu, val1 - val2)) {
            FAULT();
        }
        break;
    }
    case 0x62: {
        DLOG("executing S.XOR");
        uint32_t val1, val2;
        if (!pop_dword_from_stack(emu, &val1) || !pop_dword_from_stack(emu, &val2)) {
            FAULT();
        }
        if (!push_dword_to_stack(emu, val1 ^ val2)) {
            FAULT();
        }
        break;
    }
    case 0x63: {
        DLOG("executing S.AND");
        uint32_t val1, val2;
        if (!pop_dword_from_stack(emu, &val1) || !pop_dword_from_stack(emu, &val2)) {
            FAULT();
        }
        if (!push_dword_to_stack(emu, val1 & val2)) {
            FAULT();
        }
        break;
    }
    case 0x70: {
        DLOG("executing S.JMP");
        void* ptr = &insn_bytes[1];
        eva_t addr = *(eva_t*)ptr;
        emu->pc = addr;
        pc_taint = true;
        break;
    }
    case 0x71: {
        if (FLAG_BIT(FLAG_Z)) {
            DLOG("executing S.JEQ <taken>");
            void* ptr = &insn_bytes[1];
            eva_t addr = *(eva_t*)ptr;
            emu->pc = addr;
            pc_taint = true;
        }
        else {
            DLOG("executing S.JEQ <not taken>");
        }
        break;
    }
    case 0x72: {
        if (!FLAG_BIT(FLAG_Z)) {
            DLOG("executing S.JNE <taken>");
            void* ptr = &insn_bytes[1];
            eva_t addr = *(eva_t*)ptr;
            emu->pc = addr;
            pc_taint = true;
        }
        else {
            DLOG("executing S.JNE <not taken>");
        }
        break;
    }
    case 0x80: {
        DLOG("executing S.CMP");
        uint32_t val1, val2;
        if (!pop_dword_from_stack(emu, &val1) || !pop_dword_from_stack(emu, &val2)) {
            FAULT();
        }

        do_cmp(emu, val1, val2);
        break;
    }
    case 0xa0: {
        DLOG("executing S.SYS");

        // BUG: this doesn't check the actual syscall number that's going to be executed
        if (!can_execute_syscall(emu)) {
            ELOG("can't execute that syscall!");
            FAULT();
        }

        uint8_t syscall_number;
        if (!pop_byte_from_stack(emu, &syscall_number)) {
            FAULT();
        }

        switch (syscall_number) {
        case SYS_READ_DWORD: {
            uint32_t ret;
            if (!do_syscall_read_dword(emu, &ret)) {
                FAULT();
            }
            if (!push_dword_to_stack(emu, ret)) {
                FAULT();
            }
            break;
        }
        case SYS_READ_BYTES: {
            ELOG("unsupported syscall!");
            FAULT();
        }
        case SYS_WRITE: {
            uint8_t sz;
            eva_t ptr;
            if (!pop_dword_from_stack(emu, &ptr) || !pop_byte_from_stack(emu, &sz)) {
                FAULT();
            }

            if (!do_syscall_write(emu, ptr, sz)) {
                FAULT();
            }
            break;
        }
        case SYS_PRNG_SEED: {
            uint32_t seed;
            if (!pop_dword_from_stack(emu, &seed)) {
                FAULT();
            }

            if (!do_syscall_prng_seed(emu, seed)) {
                FAULT();
            }
            break;
        }
        case SYS_PRNG_GET: {
            uint32_t ret;
            if (!do_syscall_prng_get(emu, &ret)) {
                FAULT();
            }
            if (!push_dword_to_stack(emu, ret)) {
                FAULT();
            }
            break;
        }
        case SYS_FLAG: {
            if (!do_syscall_flag(emu)) {
                FAULT();
            }
            break;
        }
        case SYS_MMAP: {
            eva_t req_base, base;
            if (!pop_dword_from_stack(emu, &req_base)) {
                FAULT();
            }
            if (!do_syscall_mmap(emu, req_base, &base)) {
                FAULT();
            }
            if (!push_dword_to_stack(emu, base)) {
                FAULT();
            }
            break;
        }
        default: {
            ELOG("bad syscall!");
            FAULT();
        }
        }

        break;
    }
    case 0xff: {
        DLOG("executing S.HLT");
        if (memcmp(&insn_bytes[1], "\xff\xff\xff\xff", 4) != 0) {
            ELOG("invalid S.HLT");
            FAULT();
        }
        return false;
    }
    default:
        ELOG("invalid StackVM instruction, pc=%#x leader=%#x", emu->pc, insn_bytes[0]);
        FAULT();
    }

    if (!pc_taint) emu->pc += 5;
    return true;
}

bool execute_regvm_insn(emulator_t* emu) {
    uint8_t leader, prefix = 0;
    if (!read_byte_at_eva(emu, emu->pc++, &leader)) {
        FAULT();
    }

    // check if we have a prefix byte
    if ((leader >> 4) == 0xa) {
        prefix = leader & 0xf;
        if (!read_byte_at_eva(emu, emu->pc++, &leader)) {
            FAULT();
        }
    }

    if ((leader & 0xc0) == 0xc0) {
        DLOG("executing R.MOV");

        uint8_t dst_type, src_type;
        dst_type = (leader >> 3) & 0x7;
        src_type = leader & 0x7;

        bool deref_dst, deref_src;
        deref_dst = prefix >> 2;
        deref_src = prefix & 3;

        uint32_t src;
        if (src_type < 4) {
            src = emu->gp_regs[src_type];
        }
        else if (src_type == 4) {  // ADDR
            eva_t addr;
            if (!read_dword_at_eva(emu, emu->pc, &addr)) {
                FAULT();
            }
            emu->pc += 4;
            if (!read_dword_at_eva(emu, addr, &src)) {
                FAULT();
            }
        }
        else if (src_type == 5) {  // IMM
            if (!read_dword_at_eva(emu, emu->pc, &src)) {
                FAULT();
            }
            emu->pc += 4;
        }
        else if (src_type == 6) {  // sp
            src = emu->sp;
        }
        else {
            FAULT();
        }
        if (deref_src) {
            if (src_type < 4 || src_type == 6) {
                if (!read_dword_at_eva(emu, src, &src)) {
                    FAULT();
                }
            }
            else {
                FAULT();
            }
        }

        if (deref_dst) {
            if (dst_type < 4) {
                if (!write_dword_to_eva(emu, emu->gp_regs[dst_type], src)) {
                    FAULT();
                }
            }
            else {
                FAULT();
            }
        }
        else {
            if (dst_type < 4) {
                emu->gp_regs[dst_type] = src;
            }
            else if (dst_type == 4 && src_type != 6) {  // ADDR (only valid if src is not sp)
                eva_t addr;
                if (!read_dword_at_eva(emu, emu->pc, &addr)) {
                    FAULT();
                }
                emu->pc += 4;
                if (!write_dword_to_eva(emu, addr, src)) {
                    FAULT();
                }
            }
            else {
                FAULT();
            }
        }
    }
    else if (leader >= 0x11 && leader <= 0x14) {
        DLOG("executing R.PUSH r");

        if (!push_dword_to_stack(emu, emu->gp_regs[leader - 0x11])) {
            FAULT();
        }
    }
    else if (leader >= 0x15 && leader <= 0x18) {
        DLOG("executing R.POP");

        uint32_t val;
        if (!pop_dword_from_stack(emu, &val)) {
            FAULT();
        }
        emu->gp_regs[leader - 0x15] = val;
    }
    else if (leader >> 4 == 7) {
        DLOG("executing R.CMP r, r");
        uint8_t src_reg, dst_reg;
        dst_reg = (leader >> 2) & 0x3;
        src_reg = leader & 0x3;

        do_cmp(emu, emu->gp_regs[dst_reg], emu->gp_regs[src_reg]);
    }
    else if (leader >> 4 == 8) {
        DLOG("executing R.CMP r, i");
        uint8_t reg = leader & 0x3;
        uint32_t imm;
        if (!read_dword_at_eva(emu, emu->pc, &imm)) {
            FAULT();
        }
        emu->pc += 4;

        do_cmp(emu, emu->gp_regs[reg], imm);
    }
    else {
        switch (leader) {
        case 0x00: {
            DLOG("executing R.HLT");
            return false;
        }
        case 0x01: {
            DLOG("executing R.SYS");

            if (!can_execute_syscall(emu)) {
                ELOG("can't execute that syscall!");
                FAULT();
            }

            switch (emu->gp_regs[REG_A]) {
            case SYS_READ_DWORD: {
                uint32_t val;
                if (!do_syscall_read_dword(emu, &val)) {
                    FAULT();
                }
                emu->gp_regs[REG_A] = val;
                break;
            }
            case SYS_READ_BYTES: {
                if (!do_syscall_read_bytes(emu, emu->gp_regs[REG_B], emu->gp_regs[REG_C])) {
                    FAULT();
                }
                break;
            }
            case SYS_WRITE: {
                if (!do_syscall_write(emu, emu->gp_regs[REG_B], emu->gp_regs[REG_C])) {
                    FAULT();
                }
                break;
            }
            case SYS_PRNG_SEED: {
                if (!do_syscall_prng_seed(emu, emu->gp_regs[REG_B])) {
                    FAULT();
                }
                break;
            }
            case SYS_PRNG_GET: {
                uint32_t val;
                if (!do_syscall_prng_get(emu, &val)) {
                    FAULT();
                }
                emu->gp_regs[REG_A] = val;
                break;
            }
            case SYS_FLAG: {
                ELOG("unsupported syscall!");
                FAULT();
            }
            case SYS_MMAP: {
                eva_t val;
                if (!do_syscall_mmap(emu, emu->gp_regs[REG_B], &val)) {
                    FAULT();
                }
                emu->gp_regs[REG_A] = val;
                break;
            }
            default: {
                ELOG("bad syscall!");
                FAULT();
            }
            }

            break;
        }
        case 0x10: {
            DLOG("executing R.PUSH i");
            uint32_t val;
            if (!read_dword_at_eva(emu, emu->pc, &val)) {
                FAULT();
            }
            emu->pc += 4;
            if (!push_dword_to_stack(emu, val)) {
                FAULT();
            }
            break;
        }
        case 0x20: {
            DLOG("executing R.ADD r, r");
            uint8_t regs;
            if (!read_byte_at_eva(emu, emu->pc++, &regs)) {
                FAULT();
            }

            uint8_t src_reg, dst_reg;
            src_reg = ((regs & 0xf) - 1) & 3;
            dst_reg = ((regs >> 4) - 1) & 3;

            emu->gp_regs[dst_reg] += emu->gp_regs[src_reg];
            break;
        }
        case 0x21: {
            DLOG("executing R.ADD r, i");
            uint8_t regs;
            uint32_t val;
            if (!read_byte_at_eva(emu, emu->pc++, &regs)) {
                FAULT();
            }
            if (!read_dword_at_eva(emu, emu->pc, &val)) {
                FAULT();
            }
            emu->pc += 4;

            // BUG: you can oob the reg number to write past the gp_regs array
            // (this bug is present in several arthmetic reg ops)
            emu->gp_regs[((regs >> 4) - 1)] += val;
            break;
        }
        case 0x30: {
            DLOG("executing R.SUB r, r");
            uint8_t regs;
            if (!read_byte_at_eva(emu, emu->pc++, &regs)) {
                FAULT();
            }

            uint8_t src_reg, dst_reg;
            src_reg = ((regs & 0xf) - 1);
            dst_reg = ((regs >> 4) - 1);

            emu->gp_regs[dst_reg] -= emu->gp_regs[src_reg];
            break;
        }
        case 0x31: {
            DLOG("executing R.SUB r, i");
            uint8_t regs;
            uint32_t val;
            if (!read_byte_at_eva(emu, emu->pc++, &regs)) {
                FAULT();
            }
            if (!read_dword_at_eva(emu, emu->pc, &val)) {
                FAULT();
            }
            emu->pc += 4;

            uint8_t reg_num = (regs >> 4) - 1;
            switch (reg_num) {
            case REG_A:
            case REG_B:
            case REG_C:
            case REG_D:
                emu->gp_regs[reg_num] -= val;
                break;
            case 4:
                emu->sp -= val;
                break;
            default:
                FAULT();
            }

            break;
        }
        case 0x40: {
            DLOG("executing R.XOR r, r");
            uint8_t regs;
            if (!read_byte_at_eva(emu, emu->pc++, &regs)) {
                FAULT();
            }

            uint8_t src_reg, dst_reg;
            src_reg = ((regs & 0xf) - 1);
            dst_reg = ((regs >> 4) - 1);

            emu->gp_regs[dst_reg] ^= emu->gp_regs[src_reg];
            break;
        }
        case 0x41: {
            DLOG("executing R.XOR r, i");
            uint8_t regs;
            uint32_t val;
            if (!read_byte_at_eva(emu, emu->pc++, &regs)) {
                FAULT();
            }
            if (!read_dword_at_eva(emu, emu->pc, &val)) {
                FAULT();
            }
            emu->pc += 4;

            emu->gp_regs[((regs >> 4) - 1)] ^= val;
            break;
        }
        case 0x50: {
            DLOG("executing R.MUL r, r");
            uint8_t regs;
            if (!read_byte_at_eva(emu, emu->pc++, &regs)) {
                FAULT();
            }

            uint8_t src_reg, dst_reg;
            src_reg = ((regs & 0xf) - 1);
            dst_reg = ((regs >> 4) - 1);

            uint64_t res = (uint64_t)emu->gp_regs[dst_reg] * (uint64_t)emu->gp_regs[src_reg];

            emu->gp_regs[REG_A] = (uint32_t)res;
            emu->gp_regs[REG_D] = (uint32_t)(res >> 32);
            break;
        }
        case 0x51: {
            DLOG("executing R.MUL r, i");
            uint8_t regs;
            uint32_t val;
            if (!read_byte_at_eva(emu, emu->pc++, &regs)) {
                FAULT();
            }
            if (!read_dword_at_eva(emu, emu->pc, &val)) {
                FAULT();
            }
            emu->pc += 4;

            uint64_t res = (uint64_t)emu->gp_regs[((regs >> 4) - 1) & 3] * (uint64_t)val;

            emu->gp_regs[REG_A] = (uint32_t)res;
            emu->gp_regs[REG_D] = (uint32_t)(res >> 32);
            break;
        }
        case 0x60: {
            DLOG("executing R.CALL");
            eva_t ret = emu->pc + 4;
            eva_t call_tgt;
            if (!read_dword_at_eva(emu, emu->pc, &call_tgt)) {
                FAULT();
            }
            if (!push_dword_to_stack(emu, ret)) {
                FAULT();
            }
            emu->pc = call_tgt;
            break;
        }
        case 0x61: {
            DLOG("executing R.RET");
            uint8_t dwords;
            if (!read_byte_at_eva(emu, emu->pc++, &dwords)) {
                FAULT();
            }
            emu->sp += (4 * dwords);
            uint32_t val;
            if (!pop_dword_from_stack(emu, &val)) {
                FAULT();
            }
            emu->pc = val;
            break;
        }
        case 0x62: {
            if (FLAG_BIT(FLAG_Z)) {
                DLOG("executing R.JEQ <taken>");
                eva_t tgt;
                if (!read_dword_at_eva(emu, emu->pc, &tgt)) {
                    FAULT();
                }
                emu->pc = tgt;
            }
            else {
                DLOG("executing R.JEQ <not taken>");
                emu->pc += 4;
            }
            break;
        }
        case 0x63: {
            if (!FLAG_BIT(FLAG_Z)) {
                DLOG("executing R.JNE <taken>");
                eva_t tgt;
                if (!read_dword_at_eva(emu, emu->pc, &tgt)) {
                    FAULT();
                }
                emu->pc = tgt;
            }
            else {
                DLOG("executing R.JNE <not taken>");
                emu->pc += 4;
            }
            break;
        }
        case 0x64: {
            if (FLAG_BIT(FLAG_O)) {
                DLOG("executing R.JG <taken>");
                eva_t tgt;
                if (!read_dword_at_eva(emu, emu->pc, &tgt)) {
                    FAULT();
                }
                emu->pc = tgt;
            }
            else {
                DLOG("executing R.JG <not taken>");
                emu->pc += 4;
            }
            break;
        }
        case 0x68: {
            DLOG("executing R.JMP");
            eva_t tgt;
            if (!read_dword_at_eva(emu, emu->pc, &tgt)) {
                FAULT();
            }
            emu->pc = tgt;
            break;
        }
        default:
            ELOG("invalid RegVM instruction, pc=%#x leader=%#x", emu->pc, leader);
            emu->faulted = true;
            return false;
        }
    }

    return true;
}

bool execute_next_instruction(emulator_t* emu) {
    int arch = get_arch_for_insn(emu);
    if (arch == ARCH_STACKVM) {
        return execute_stackvm_insn(emu);
    }
    else if (arch == ARCH_REGVM) {
        return execute_regvm_insn(emu);
    }
    else {
        // if this gets hit call IEEE, we found a qubit on x86
        ELOG("nice qubit");
        return false;
    }
}

void dump_emulator_state(emulator_t* emu, bool include_stack) {
    printf("  ---[ PC=0x%08x SP=0x%08x | A=0x%08x B=0x%08x C=0x%08x D=0x%08x\n", emu->pc, emu->sp, emu->gp_regs[REG_A], emu->gp_regs[REG_B], emu->gp_regs[REG_C], emu->gp_regs[REG_D]);

    if (include_stack) {
        uint32_t val;

        printf("  ---[ STACK CONTENTS\n");
        for (int i = -0x8; i < 0x14; i += 4) {
            eva_t addr = emu->sp + i;
            if (!read_dword_at_eva(emu, addr, &val)) break;
            printf("\t%s0x%08x  0x%08x\n", addr == emu->sp ? "* " : "  ", addr, val);
        }
    }
}