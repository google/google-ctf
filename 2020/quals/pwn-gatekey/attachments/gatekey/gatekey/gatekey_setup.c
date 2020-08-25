/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include "internal.h"
#include "gatekey_api.h"

struct seccomp_data_patched {
  int nr;
  __u32 arch;
  __u64 instruction_pointer;
  __u64 args[6];
  __u64 pkeys;
};

#define SECCOMP_LOAD(NAME, OFFSET) \
  { .code = BPF_LD | BPF_W | BPF_ABS, .k = offsetof(struct seccomp_data_patched, NAME) + OFFSET }
#define SECCOMP_ASSERT(CMP, VALUE) \
  { .code = BPF_JMP|CMP|BPF_K, .k = (VALUE), .jf = (uint8_t)-2 }
#define SECCOMP_ACCEPT_IF(CMP, VALUE) \
  { .code = BPF_JMP|CMP|BPF_K, .k = (VALUE), .jt = (uint8_t)-1 }

extern struct open_how permitted_open_how[2];
extern void *(*__morecore)(unsigned long); /* from glibc */

/* __morecore hook to prevent any use of brk() */
static void *morecore_reject(unsigned long increment) {
  return NULL;
}

/* If you have unaligned WRPKRU/XRSTOR anywhere, this is gonna let you have a
 * really bad time. But at least the glibc I'm testing with doesn't have any of
 * those...
 * Also, this breaks lazy symbol resolution.
 */
static void clobber_insn_unless_known_safe(unsigned char *p) {
  extern unsigned char safe_wrpkru_trusted[];
  extern unsigned char safe_wrpkru_normal[];
  if (p == safe_wrpkru_trusted || p == safe_wrpkru_normal) {
    printf("  known safe\n");
    return;
  }
  printf("  clobbering\n");
  int fd = open("/proc/self/mem", O_WRONLY);
  if (fd == -1) err(1, "open mem");
  unsigned char clobber[] = {0xcc, 0xcc, 0xcc};
  if (pwrite(fd, clobber, sizeof(clobber), (unsigned long)p) != sizeof(clobber))
    err(1, "clobbering instruction failed");
  close(fd);
}

static void ensure_no_bad_insns_in_range(unsigned long start, unsigned long end) {
  printf("ensure_no_bad_insns_in_range(%lx-%lx)\n", start, end);
  for (unsigned char *p = (unsigned char *)start; p + 3 <= (unsigned char*)end; p++) {
    if (p[0] != 0x0f)
      continue;
    if (p[1] == 0x01 && p[2] == 0xef) {
      printf("WRPKRU at %p\n", p);
      clobber_insn_unless_known_safe(p);
    }
    if (p[1] == 0xae && (p[2] & 0x38) == 0x28 && (p[2] >> 6) != 3/*register-direct==LFENCE*/) {
      printf("XRSTOR at %p\n", p);
      clobber_insn_unless_known_safe(p);
    }
  }
}

static void ensure_no_bad_insns(void) {
  int maps_fd = open("/proc/self/maps", O_RDONLY);
  char maps[100000];
  int maps_len = 0;
  while (1) {
    int len = read(maps_fd, maps+maps_len, sizeof(maps)-1-maps_len);
    if (len < 0)
      err(1, "unable to read from maps");
    if (len == 0)
      break;
    maps_len += len;
  }
  maps[maps_len] = '\0';
  char *line = maps;
  unsigned long exec_start = 0, exec_end = 0;
  while (1) {
    char *next_line = strchr(line, '\n');
    if (next_line) {
      *next_line = '\0';
      next_line++;
    }

    unsigned long start, end;
    char flags[100];
    if (sscanf(line, "%lx-%lx %s", &start, &end, flags) != 3)
      errx(1, "cannot parse line '%s'", line);
    printf("got mapping: %s\n", line);
    assert(end > start);
    assert(flags[2] == '-' || flags[2] == 'x');
    assert(flags[1] == '-' || flags[2] == '-'); // W^X
    if (flags[2] == 'x' && start == exec_end) {
      exec_end = end;
    } else if (flags[2] == 'x') {
      ensure_no_bad_insns_in_range(exec_start, exec_end);
      exec_start = start;
      exec_end = end;
    }

    line = next_line;
    if (line == NULL || line[0] == '\0')
      break;
  }
  ensure_no_bad_insns_in_range(exec_start, exec_end);
  close(maps_fd);
}

void gatekey_setup(void) {
  __morecore = morecore_reject;

  ensure_no_bad_insns();

  /* Prevent exploitable recursion. */
  if (mprotect(key_gate_stack, 0x1000, PROT_NONE))
    err(1, "mprotect key_gate_stack guard page");

#ifndef INSECURE
  /* Set up trusted/normal pkey states. */
  int gatekey_idx = pkey_alloc(0, 0);
  if (gatekey_idx == -1)
    err(1, "pkey_alloc failed; please make sure your machine supports pkeys");
  gatekey_trusted_key_state = __builtin_ia32_rdpkru();
  unsigned int gatekey_write_mask = (0x2 << (2 * gatekey_idx));
  gatekey_normal_key_state = gatekey_trusted_key_state | gatekey_write_mask;

  /* Protect gatekey regions with our shiny new pkey. */
  if (pkey_mprotect(_gatekey_data_begin, _gatekey_data_end - _gatekey_data_begin, PROT_READ|PROT_WRITE, gatekey_idx))
    err(1, "protect our .data with the gatekey: pkey_mprotect(%p, 0x%lx, READ|WRITE, 0x%lx)", _gatekey_data_begin, _gatekey_data_end - _gatekey_data_begin, gatekey_idx);
  if (pkey_mprotect(_gatekey_bss_begin, _gatekey_bss_end - _gatekey_bss_begin, PROT_READ|PROT_WRITE, gatekey_idx))
    err(1, "protect our .bss with the gatekey");

  printf("trusted pkeys state: 0x%x\n", gatekey_trusted_key_state);
  printf("restricted pkeys state: 0x%x\n", gatekey_normal_key_state);
  printf("gatekey index: %d\n", gatekey_idx);
#else
  printf("INSECURE MODE ACTIVE, NOT FOR PRODUCTION USE\n");
#endif

  /*
   * Create a seccomp policy to protect gatekey stuff.
   */
  unsigned long mmap_protected_end = (unsigned long)&_end;
  assert(mmap_protected_end <= UINT_MAX);
  struct sock_filter filter[] = {
    /* must be x86-64 ABI */
    SECCOMP_LOAD(arch, 0),
    SECCOMP_ASSERT(BPF_JEQ, AUDIT_ARCH_X86_64),

    SECCOMP_LOAD(nr, 0),

    /* unconditionally acceptable syscalls */
    SECCOMP_ACCEPT_IF(BPF_JEQ, __NR_read),
    SECCOMP_ACCEPT_IF(BPF_JEQ, __NR_pread64),
    SECCOMP_ACCEPT_IF(BPF_JEQ, __NR_write),
    SECCOMP_ACCEPT_IF(BPF_JEQ, __NR_pwrite64),
    SECCOMP_ACCEPT_IF(BPF_JEQ, __NR_close),
    SECCOMP_ACCEPT_IF(BPF_JEQ, __NR_exit_group),
    SECCOMP_ACCEPT_IF(BPF_JEQ, __NR_getrandom),

    /* mmap: only non-fixed, non-executable */
    { .code = BPF_JMP|BPF_JEQ|BPF_K, .k = __NR_mmap, .jf = 4 },
    SECCOMP_LOAD(args[2], 0),
    SECCOMP_ASSERT(BPF_JEQ, PROT_READ|PROT_WRITE),
    SECCOMP_LOAD(args[3], 0),
    SECCOMP_ACCEPT_IF(BPF_JEQ, MAP_PRIVATE|MAP_ANONYMOUS),

    /* munmap: only past the end of our program mapping */
    { .code = BPF_JMP|BPF_JEQ|BPF_K, .k = __NR_munmap, .jf = 4 },
    SECCOMP_LOAD(args[0], 4),
    SECCOMP_ACCEPT_IF(BPF_JGT, 0),
    SECCOMP_LOAD(args[0], 0),
    SECCOMP_ACCEPT_IF(BPF_JGE, (uint32_t)mmap_protected_end),

#ifndef INSECURE
    /* anything else requires having the privileged key... */
    SECCOMP_LOAD(pkeys, 0),
    SECCOMP_ASSERT(BPF_JEQ, gatekey_trusted_key_state),
#endif

    /* privileged code still can't do whatever it wants, but we permit opening
     * files below cwd and open fds
     */
    SECCOMP_LOAD(nr, 0),
    SECCOMP_ASSERT(BPF_JEQ, __NR_openat2),
    SECCOMP_LOAD(args[2], 4),
    SECCOMP_ASSERT(BPF_JEQ, ((unsigned long)&permitted_open_how)>>32),
    SECCOMP_LOAD(args[2], 0),
    SECCOMP_ACCEPT_IF(BPF_JEQ, (uint32_t)(unsigned long)permitted_open_how),
    SECCOMP_ACCEPT_IF(BPF_JEQ, (uint32_t)(unsigned long)(permitted_open_how+1)),

    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  int filter_len = sizeof(filter)/sizeof(filter[0]);
  /* interpret negative jumps as end-of-program-relative */
  for (int i=0; i<filter_len; i++) {
    if (filter[i].jf >= (uint8_t)-8)
      filter[i].jf = filter_len + (int8_t)filter[i].jf - (i + 1);
    if (filter[i].jt >= (uint8_t)-8)
      filter[i].jt = filter_len + (int8_t)filter[i].jt - (i + 1);
  }
  struct sock_fprog prog = {
    .filter = filter,
    .len = sizeof(filter)/sizeof(filter[0])
  };

  /* turn on seccomp filter */
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
    err(1, "set NNP");
  if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_LOG, &prog))
    err(1, "engage seccomp filter");

  /* switch to untrusted protection keys state */
  gatekey_exit_trusted(0);
}
