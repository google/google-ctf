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
#include <stdint.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>

#define NULL ((void*)0)
typedef uint64_t size_t;

// Minimal effort C/asm level calling convention translation to syscall calling
// convention.
extern uint64_t syscall0(int syscall);
extern uint64_t syscall1(
    int syscall, uint64_t rdi
);
extern uint64_t syscall2(
    int syscall, uint64_t rdi, uint64_t rsi
);
extern uint64_t syscall3(
    int syscall, uint64_t rdi, uint64_t rsi, uint64_t rdx
);
extern uint64_t syscall4(
    int syscall, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t r10
);
extern uint64_t syscall5(
    int syscall, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t r10,
    uint64_t r8
);
extern uint64_t syscall6(
    int syscall, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t r10,
    uint64_t r8, uint64_t r9
);

extern void write_stack_guard(uint64_t new_stack_guard);

__asm("                                \n\
  .globl syscall0                      \n\
  .type syscall0, @function            \n\
  syscall0:                            \n\
    mov %eax, %edi                     \n\
    syscall                            \n\
    ret                                \n\
                                       \n\
  .globl syscall1                      \n\
  .type syscall1, @function            \n\
  syscall1:                            \n\
    mov %eax, %edi                     \n\
    mov %rdi, %rsi                     \n\
    syscall                            \n\
    ret                                \n\
                                       \n\
.globl syscall2                        \n\
  .type syscall2, @function            \n\
  syscall2:                            \n\
    mov %eax, %edi                     \n\
    mov %rdi, %rsi                     \n\
    mov %rsi, %rdx                     \n\
    syscall                            \n\
    ret                                \n\
                                       \n\
.globl syscall3                        \n\
  .type syscall3, @function            \n\
  syscall3:                            \n\
    mov %eax, %edi                     \n\
    mov %rdi, %rsi                     \n\
    mov %rsi, %rdx                     \n\
    mov %rdx, %rcx                     \n\
    syscall                            \n\
    ret                                \n\
                                       \n\
.globl syscall4                        \n\
  .type syscall4, @function            \n\
  syscall4:                            \n\
    mov %eax, %edi                     \n\
    mov %rdi, %rsi                     \n\
    mov %rsi, %rdx                     \n\
    mov %rdx, %rcx                     \n\
    mov %r10, %r8                      \n\
    syscall                            \n\
    ret                                \n\
                                       \n\
.globl syscall5                        \n\
  .type syscall5, @function            \n\
  syscall5:                            \n\
    mov %eax, %edi                     \n\
    mov %rdi, %rsi                     \n\
    mov %rsi, %rdx                     \n\
    mov %rdx, %rcx                     \n\
    mov %r10, %r8                      \n\
    mov %r8,  %r9                      \n\
    syscall                            \n\
    ret                                \n\
                                       \n\
  .globl syscall6                      \n\
  .type syscall6, @function            \n\
  syscall6:                            \n\
    mov %eax, %edi                     \n\
    mov %rdi, %rsi                     \n\
    mov %rsi, %rdx                     \n\
    mov %rdx, %rcx                     \n\
    mov %r10, %r8                      \n\
    mov %r8,  %r9                      \n\
    mov %r9, qword ptr [%rsp+8]        \n\
    syscall                            \n\
    ret                                \n\
                                       \n\
  .globl write_stack_guard             \n\
  .type write_stack_guard, @function   \n\
  write_stack_guard:                   \n\
    mov qword ptr fs:0x28, rdi         \n\
    ret                                \n\
");

void sys_exit(int code) {
  syscall1(60, code);
}

size_t sys_write(int fd, const void *buf, size_t count) {
  return syscall3(1, (uint64_t)fd, (uint64_t)buf, count);
}

size_t sys_read(int fd, void *buf, size_t count) {
  return syscall3(0, (uint64_t)fd, (uint64_t)buf, count);
}

#define PROT_NONE  0
#define PROT_READ  1
#define PROT_WRITE 2
#define PROT_EXEC  4
#define MAP_PRIVATE 2
#define MAP_FIXED 0x10
#define MAP_FIXED_NOREPLACE 0x100000
#define MAP_ANON  0x20

void *sys_mmap(
    uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags,
    uint64_t fd, uint64_t off) {
  return (void*)syscall6(9, addr, len, prot, flags, fd, off);
}

void sys_mprotect(uint64_t addr, uint64_t len, uint64_t prot) {
  syscall3(10, addr, len, prot);
}

void sys_munmap(uint64_t addr, uint64_t len) {
  syscall2(11, addr, len);
}

int sys_open(const char *fname, int flags, int mode) {
  return (int)syscall3(2, (uint64_t)fname, flags, mode);
}

void sys_close(int fd) {
  syscall1(3, (uint64_t)fd);
}

void sys_lseek(int fd, size_t offset, unsigned int origin) {
  syscall3(8, (uint64_t)fd, offset, origin);
}

void sys_fstat(int fd, struct stat *statbuf) {
  syscall2(5, (uint64_t)fd, (uint64_t)statbuf);
}

void sys_getrandom(void *buf, size_t buflen, unsigned int flags) {
  syscall3(318, (uint64_t)buf, buflen, flags);
}

extern uint8_t __executable_start;
extern uint8_t _end;

#define MAX_O 64
#define MAX_EXPORT 64

const char *files[] = {
  "main.o",
  "syscalls.o",
  "guard.o",
  "basic.o",
  "game.o",
  "res.o",
  "debug.o",
  NULL
};

struct o_info_st {
  uint64_t dst_addr;
} o_info[MAX_O];

struct o_ctx_st {
  int fd;
  uint8_t *elf;       // These two point at
  Elf64_Ehdr *ehdr;   // the same things.
  size_t elf_sz;
  Elf64_Shdr *s;
  uint8_t *shstrtab;
  uint8_t *strtab;
  uint8_t *symtab;
  size_t symtab_global_idx;
  size_t symtab_size;
  uint64_t dst_addr;
  uint8_t *vm_plt;
  uint8_t *vm_plt_iter;
  uint8_t *vm_sec_addr[32];
  size_t vm_sec_size[32];
} o_ctx[MAX_O];

struct export_info_st {
  char name[32];
  uint64_t addr;
} export_info[MAX_EXPORT];
uint32_t export_count;

uint64_t rand_state;

int strcmp(const char *a, const char *b) {
  for (;;) {
    if (*a != *b) {
      return *a - *b;
    }

    if (*a == '\0') {
      return 0;
    }

    a++; b++;
  }
}

char *strcpy(char *dst, const char *src) {
  char *org_dst = dst;
  do {
    *dst++ = *src;
  } while (*src++);
  return org_dst;
}

size_t strlen(const char *s) {
  size_t i = 0;
  while (*s++) i++;
  return i;
}

int puts(const char *s) {
  sys_write(1, s, strlen(s));
  sys_write(1, "\n", 1);
  return 0;
}

void die(const char *err) {
  puts(err);
  sys_exit(123);
}

static inline uint8_t rand_extract_bit(int n) {
  return (rand_state >> n) & 1;
}

static uint8_t rand_get_bit(void) {
  uint8_t new_bit = (
      1 ^
      rand_extract_bit(63) ^
      rand_extract_bit(61) ^
      rand_extract_bit(60) ^
      rand_extract_bit(58)
  );

  rand_state = (rand_state << 1) | new_bit;
  return new_bit;
}

uint64_t rand(int number_of_bits) {
  uint64_t bits = 0;
  for (int i = 0; i < number_of_bits; i++) {
    bits <<= 1;
    bits |= rand_get_bit();
  }
  return bits;
}

void *mmap_or_die(uint64_t addr, uint64_t sz, uint64_t prot) {
  void *res = sys_mmap(
      addr, sz, prot,
      MAP_FIXED_NOREPLACE|MAP_PRIVATE|MAP_ANON, 0, 0
  );
  if (res == NULL) {
    die("mmap_or_die");
  }

  return res;
}

void export_add(const char *name, uint64_t addr) {
  struct export_info_st *e = &export_info[export_count++];
  strcpy(e->name, name);
  e->addr = addr;
}

uint64_t export_get(const char *name) {
  for (uint32_t i = 0; i < export_count; i++) {
    if (strcmp(name, export_info[i].name) == 0) {
      return export_info[i].addr;
    }
  }

  return 0;
}

uint64_t aslr_get_addr(uint32_t page_count) {
  size_t sz = 4096 * page_count;
  for (;;) {
    uint64_t candidate_addr = rand(12) << 28;

    // Try to allocate memory.
    uint64_t addr = (uint64_t)sys_mmap(
        candidate_addr, sz,
        PROT_READ|PROT_WRITE, MAP_FIXED_NOREPLACE|MAP_PRIVATE|MAP_ANON, 0, 0);
    if (addr >= 0xfffffffffffff000ULL) {
      // Can't allocate for some reason.
      puts("note: candidate address occupied");
      continue;
    }

    if (addr != candidate_addr) {
      die("No idea. Should not happen.");
    }

    sys_munmap(addr, sz);
    return addr;
  }
}

void load_o_phase_1(struct o_ctx_st *ctx, const char *fname) {
  ctx->fd = sys_open(fname, 0, 0);
  if (ctx->fd < 0) {
    die("could not open file");
  }

  struct stat statbuf;
  sys_fstat(ctx->fd, &statbuf);
  ctx->elf_sz = (statbuf.st_size + 0xfff) & ~0xfffULL;
  ctx->elf = sys_mmap(0, ctx->elf_sz, PROT_READ, MAP_PRIVATE, ctx->fd, 0);
  ctx->ehdr = (Elf64_Ehdr*)ctx->elf;

  ctx->dst_addr = aslr_get_addr(ctx->ehdr->e_shnum + 1);
  uint64_t dst_iter = ctx->dst_addr;

  // Allocate plt section.
  ctx->vm_plt = mmap_or_die(dst_iter, 4096, PROT_READ|PROT_WRITE);
  ctx->vm_plt_iter = ctx->vm_plt;
  dst_iter += 4096;

  ctx->s = (Elf64_Shdr*)(ctx->elf + ctx->ehdr->e_shoff);
  ctx->shstrtab = ctx->elf + ctx->s[ctx->ehdr->e_shstrndx].sh_offset;

  // First pass:
  // - Allocate memory for each section and copy the data.
  // - Note the address of each section by index.
  // - Find the .symtab and .strtab sections.
  // - Note sections with relocations.
  for (uint16_t i = 0; i < ctx->ehdr->e_shnum; i++) {
    Elf64_Shdr *section = &ctx->s[i];

    switch (section->sh_type) {
      case SHT_NULL:
      case SHT_RELA:
        // Ignore, go to the next one.
        continue;

      case SHT_SYMTAB:
        // Mark for future processing.
        if (ctx->symtab == NULL) {
          ctx->symtab = ctx->elf + section->sh_offset;
          ctx->symtab_size = section->sh_size;
          ctx->symtab_global_idx = section->sh_info;
        } else {
          die("duplicate symtabs");
        }
        break;

      case SHT_STRTAB:
        // Mark for future processing.
        if (i != ctx->ehdr->e_shstrndx) {
          if (ctx->strtab == NULL) {
            ctx->strtab = ctx->elf + section->sh_offset;
          } else {
            die("duplicate strtabs");
          }
        }
        break;

      case SHT_PROGBITS:
      case SHT_NOBITS:
      case SHT_NOTE:
        // Will be processed later.
        break;

      default:
        die("unknown section type");
    }

    if ((section->sh_flags & SHF_ALLOC) == 0) {
      continue;
    }

    if ((section->sh_flags & SHF_MASKPROC) != 0) {
      die("SHF_MASKPROC");
    }

    // Allocate all sections read/write for now. Attributes will be fixed later.
    ctx->vm_sec_size[i] = (section->sh_size + 4095) & ~0xfffULL;
    if (ctx->vm_sec_size[i] == 0) {
      // puts("note: section empty");
      continue;
    }

    ctx->vm_sec_addr[i] = mmap_or_die(
        dst_iter, ctx->vm_sec_size[i], PROT_READ|PROT_WRITE
    );
    dst_iter += ctx->vm_sec_size[i];

    // Copy data, if any.
    if (section->sh_type != SHT_NOBITS) {
      uint8_t *src = ctx->elf + section->sh_offset;
      uint8_t *dst = ctx->vm_sec_addr[i];
      for (uint64_t j = 0; j < section->sh_size; j++) {
        *dst++ = *src++;
      }
    }
  }

  if (ctx->symtab == NULL) {
    puts(".symtab section not found - that's somewhat unlikely");
  }

  if (ctx->strtab == NULL) {
    puts(".strtab section not found - that's somewhat unlikely");
  }

  // Find all the exported symbols.
  for (size_t i = ctx->symtab_global_idx;
       i < ctx->symtab_size / sizeof(Elf64_Sym);
       i++) {
    Elf64_Sym *sym = (Elf64_Sym*)(ctx->symtab + i * sizeof(Elf64_Sym));

    if (ELF64_ST_BIND(sym->st_info) == STB_LOCAL) {
      continue;
    }

    if (ELF64_ST_TYPE(sym->st_info) != STT_OBJECT &&
        ELF64_ST_TYPE(sym->st_info) != STT_FUNC) {
      continue;
    }

    const char *sym_name = (const char*)(ctx->strtab + sym->st_name);

    uint8_t *dst_section = ctx->vm_sec_addr[sym->st_shndx];
    if (dst_section == NULL) {
      die("symbol refers to section that is not loaded");
    }

    export_add(sym_name, (uint64_t)(dst_section + sym->st_value));
  }
}

void load_o_phase_2(struct o_ctx_st *ctx, const char *fname) {
  // Second phase:
  // - Apply relocations.
  // - Link imports.
  // - Add jump gates to PLT section if needed.
  (void)fname;
  for (uint16_t i = 0; i < ctx->ehdr->e_shnum; i++) {
    Elf64_Shdr *section = &ctx->s[i];

    if (section->sh_type != SHT_RELA) {
      continue;
    }

    //Elf64_Shdr *target_section = &ctx->s[section->sh_info];
    uint8_t *target_data = ctx->vm_sec_addr[section->sh_info];

    uint8_t *r = ctx->elf + section->sh_offset;
    for (size_t i = 0; i < section->sh_size; i += sizeof(Elf64_Rela)) {
      Elf64_Rela *rel = (Elf64_Rela*)&r[i];

      Elf64_Sym *sym =
          (Elf64_Sym*)(ctx->symtab +
                       ELF64_R_SYM(rel->r_info) * sizeof(Elf64_Sym));
      const char *sym_name = ELF64_ST_TYPE(sym->st_info) == STT_SECTION ?
          (const char*)(ctx->shstrtab + ctx->s[sym->st_shndx].sh_name) :
          (const char*)(ctx->strtab + sym->st_name);

      uint64_t sym_value;
      if (sym->st_shndx == 0) {
       sym_value = export_get(sym_name);
      if (sym_value == 0) {
          puts("symbol not found:");
          puts(sym_name);
          die("");
        }
      } else {
        sym_value = (uint64_t)ctx->vm_sec_addr[sym->st_shndx] + sym->st_value;
      }

      uint8_t *target_word8 = target_data + rel->r_offset;
      //uint16_t *target_word16 = (uint16_t*)target_word8;
      uint32_t *target_word32 = (uint32_t*)target_word8;
      uint64_t *target_word64 = (uint64_t*)target_word8;

      uint64_t plt_value = ~0ULL;
      if (ELF64_R_TYPE(rel->r_info) == R_X86_64_PLT32) {
        plt_value = (uint64_t)ctx->vm_plt_iter;
        *ctx->vm_plt_iter++ = 0xff;  // jmp [rip+2]
        *ctx->vm_plt_iter++ = 0x25;
        *ctx->vm_plt_iter++ = 0x02;
        *ctx->vm_plt_iter++ = 0x00;
        *ctx->vm_plt_iter++ = 0x00;
        *ctx->vm_plt_iter++ = 0x00;
        *ctx->vm_plt_iter++ = 0xcc;  // int3
        *ctx->vm_plt_iter++ = 0xcc;  // int3
        *(uint64_t*)ctx->vm_plt_iter = sym_value;
        ctx->vm_plt_iter += 8;
      }

      switch (ELF64_R_TYPE(rel->r_info)) {
        case R_X86_64_PC32:  // S + A - P
          *target_word32 = (uint32_t)(
              sym_value + rel->r_addend - (uint64_t)target_word8);
          break;

        case R_X86_64_PLT32:  // L + A - P
          *target_word32 = (uint32_t)(
            plt_value + rel->r_addend - (uint64_t)target_word8);
          break;

        case R_X86_64_64:  // S + A
          *target_word64 = sym_value + rel->r_addend;
          break;

        default:
          die("unsupported relocation entry");
      }
    }
  }
}

void load_o_phase_final(struct o_ctx_st *ctx, const char *fname) {
  // Last pass:
  // - Fix memory protection attributes.
  (void)fname;
  for (uint16_t i = 0; i < ctx->ehdr->e_shnum; i++) {
    if (ctx->vm_sec_addr[i] == NULL) {
      continue;
    }

    Elf64_Shdr *section = &ctx->s[i];

    uint32_t vm_prot = PROT_READ;
    if ((section->sh_flags & SHF_WRITE)) {
      vm_prot |= PROT_WRITE;
    }
    if ((section->sh_flags & SHF_EXECINSTR)) {
      vm_prot |= PROT_EXEC;
    }

    sys_mprotect((uint64_t)ctx->vm_sec_addr[i], ctx->vm_sec_size[i], vm_prot);
  }

  sys_munmap((uint64_t)ctx->elf, ctx->elf_sz);
  sys_close(ctx->fd);

  sys_mprotect((uint64_t)ctx->vm_plt, 0x1000, PROT_READ|PROT_EXEC);
}

void init_stack_guard(void) {
  void *fs = sys_mmap(
      0, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0
  );
  syscall2(158, 0x1002, (uint64_t)fs);  // Set FS base.
  write_stack_guard(rand(64));
}

void pivot_to_main(uint64_t main) {
  // Prepare the staging gate.
  uint8_t *gate = sys_mmap(
      0, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0
  );

  uint64_t exec_start = (uint64_t)&__executable_start;
  uint64_t exec_end = (((uint64_t)&_end) + 0xfff) & ~0xfffULL;
  uint64_t exec_sz = exec_end - exec_start;

  uint8_t *p = gate;
  *p++ = 0x31;  // xor eax,eax
  *p++ = 0xc0;
  *p++ = 0xb0;  // mov al, 0xb  (unmap)
  *p++ = 0x0b;
  *p++ = 0x48;  // mov rdi, exec_start
  *p++ = 0xbf;
  *(uint64_t*)p = exec_start; p += 8;
  *p++ = 0x48;  // mov rsi, exec_sz
  *p++ = 0xbe;
  *(uint64_t*)p = exec_sz; p += 8;
  *p++ = 0x0f;  // syscall
  *p++ = 0x05;
  *p++ = 0x48;  // mov rax, main
  *p++ = 0xb8;
  *(uint64_t*)p = main; p += 8;
  *p++ = 0xff;  // call rax
  *p++ = 0xd0;
  *p++ = 0x89;  // mov edi, eax
  *p++ = 0xc7;
  *p++ = 0x31;  // xor eax, eax
  *p++ = 0xc0;
  *p++ = 0xb0;  // mov al, 0x3c  (exit)
  *p++ = 0x3c;
  *p++ = 0x0f;  // syscall
  *p++ = 0x05;

  // Jump through the gate.
  sys_mprotect((uint64_t)gate, 4096, PROT_READ|PROT_EXEC);
  ((void(*)(void))gate)();
}

void zeromem(void *buffer, size_t sz) {
  uint8_t *p = buffer;
  for (size_t i = 0; i < sz; i++) {
    p[i] = 0;
  }
}

void _start() {
  // Init rand.
  sys_getrandom(&rand_state, 8, /*flags=*/2);
  init_stack_guard();

  // Load images.
  for (int i = 0; files[i]; i++) {
    load_o_phase_1(&o_ctx[i], files[i]);
  }

  // Link images.
  for (int i = 0; files[i]; i++) {
    load_o_phase_2(&o_ctx[i], files[i]);
  }

  // Finalize and clean.
  for (int i = 0; files[i]; i++) {
    load_o_phase_final(&o_ctx[i], files[i]);
  }

  uint64_t main = export_get("main");

  // Clear state.
  zeromem(o_info, sizeof(o_info));
  zeromem(o_ctx, sizeof(o_ctx));
  zeromem(export_info, sizeof(export_info));
  export_count = 0;
  rand_state = 0;

  pivot_to_main(main);
  // This place is never reached.
}
