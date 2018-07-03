/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <asm/ldt.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/resource.h>

#include "sandbox.h"
#include "seccomp-bpf.h"

#include "asm.h"
#include "kernel_entry.h"

#define MARKER          "deadbeef"
#define MARKER_SIZE     (sizeof(MARKER) - 1)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

int modify_ldt(int func, void *ptr, unsigned long bytecount);


static void setup_userland(void)
{
  struct user_desc desc;
  unsigned char *q;
  int flags;
  void *p;

  memset(&desc, 0, sizeof(desc));
  desc.entry_number = 1;
  desc.base_addr = 0;
  desc.limit = (1L << 32) - 1;
  desc.seg_32bit = 1;
  desc.contents = 2;
  desc.read_exec_only = 0;
  desc.limit_in_pages = 1;
  desc.seg_not_present = 0;
  desc.useable = 1;

  if (modify_ldt(1, &desc, sizeof(desc)) != 0)
    err(1, "failed to setup 32-bit segment");

  /* setup trampoline code to kernel */
  flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT | MAP_FIXED;
  if (mmap(LAST_PAGE, PAGE_SIZE, PROT_WRITE, flags, -1, 0) != LAST_PAGE)
    err(1, "mmap");

  memset(LAST_PAGE, '\x90', PAGE_SIZE);
  q = (unsigned char *)LAST_PAGE + PAGE_SIZE - asm_bin_len - 1;
  memcpy(q, asm_bin, asm_bin_len);

  if (mprotect(LAST_PAGE, PAGE_SIZE, PROT_READ | PROT_EXEC) != 0)
    err(1, "mprotect");

  /* setup page for user-supplied code */
  flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT | MAP_FIXED;
  p = mmap(USER_CODE, PAGE_SIZE, PROT_READ | PROT_EXEC, flags, -1, 0);
  if (p != USER_CODE)
    err(1, "mmap");

    /* setup rw pages for user stack */
  flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT | MAP_FIXED;
  p = mmap(USER_STACK, STACK_SIZE, PROT_READ | PROT_WRITE, flags, -1, 0);
  if (p != USER_STACK)
    err(1, "mmap");
}

/* set up first kernel page */
static void setup_kernelland(void)
{
  unsigned int i, j;
  unsigned char *p;
  void *stack;
  int flags;

  flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
  if (mmap(KERNEL_PAGE, PAGE_SIZE, PROT_WRITE, flags, -1, 0) != KERNEL_PAGE)
    err(1, "mmap");

  flags = MAP_PRIVATE | MAP_ANONYMOUS;
  stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, flags, -1, 0);
  if (stack == MAP_FAILED)
    err(1, "mmap");

  /* patch kernel function and stack addresses */
  p = kernel_entry_bin;
  j = 0;
  for (i = 0; i < kernel_entry_bin_len - sizeof(long) && j != 3; i++) {
    if (*(unsigned long *)p == 0xdeadbeefdeadc0de) {
      *(unsigned long *)p = (unsigned long)&kernel;
      j |= 1;
    }
    else if (*(unsigned long *)p == 0xdeadbeefdeaddead) {
      *(unsigned long *)p = (unsigned long)stack + STACK_SIZE - sizeof(long);
      j |= 2;
    }
    p++;
  }

  if (j != 3)
    errx(1, "failed to patch stuff");

  memcpy(KERNEL_PAGE, kernel_entry_bin, kernel_entry_bin_len);

  if (mprotect(KERNEL_PAGE, PAGE_SIZE, PROT_READ | PROT_EXEC) != 0)
    err(1, "mprotect");
}

/* ensure that no unexpected mapping is below 4G */
static void check_proc_maps(int verbose)
{
  unsigned long start, end;
  char line[4096];
  char flags[32];
  FILE *fp;

  fp = fopen("/proc/self/maps", "r");
  if (fp == NULL)
    err(1, "failed to open /proc/self/maps");

  while (1) {
    if (fgets(line, sizeof(line), fp) == NULL)
      break;

    if (sscanf(line, "%lx-%lx %31s %*x %*x:%*x %*u", &start, &end, flags) != 3)
      errx(1, "fscanf failed");

    if (start < (1L << 32)) {
      if (verbose)
        printf("%s", line);
      if (!(start == (unsigned long)USER_STACK && end == (unsigned long)USER_STACK + STACK_SIZE) &&
          !(start == (unsigned long)USER_CODE && end == (unsigned long)USER_CODE + PAGE_SIZE) &&
          !(start == (unsigned long)LAST_PAGE && end == (unsigned long)KERNEL_PAGE + PAGE_SIZE))
        errx(1, "unexpected mapping");
    }
  }

  fclose(fp);
}

static void install_seccomp(void)
{
  struct sock_filter filter[] = {
    /* No syscalls must be made if instruction pointer is lower than 4G.
     * That should not be necessary, but better be safe. */
    VALIDATE_IP,
    /* Grab the system call number. */
    EXAMINE_SYSCALL,
    /* List allowed syscalls. */
    ALLOW_SYSCALL(read),
    ALLOW_SYSCALL(write),
    ALLOW_SYSCALL(open),
    ALLOW_SYSCALL(close),
    ALLOW_SYSCALL(mprotect),
    ALLOW_SYSCALL(exit_group),
    KILL_PROCESS,
  };

  struct sock_fprog prog = {
    .len = (unsigned short)ARRAY_SIZE(filter),
    .filter = filter,
  };

  struct rlimit limit;
  if (getrlimit(RLIMIT_NPROC, &limit) != 0)
    err(1, "getrlimit");

  limit.rlim_cur = 0;
  if (setrlimit(RLIMIT_NPROC, &limit) != 0)
    err(1, "setrlimit");

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    err(1, "prctl(NO_NEW_PRIVS)");

  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0)
    err(1, "prctl(SECCOMP)");
}

static struct opcode { char *name; char opcode; } opcodes[] = {
  { "iret",          0xcf },
  { "far jmp",       0xea },
  { "far call",      0x9a },
  { "far ret",       0xca },
  { "far ret",       0xcb },
  { "far jmp/call",  0xff },
  { NULL,            0x00 },
};

/* copy 32-bit code to r-x memory */
static void copy_user_code(char *code, size_t size)
{
  struct opcode *opcode;

  /* ensure that there is no forbidden instructions */
  for (opcode = opcodes; opcode->name != NULL; opcode++) {
    if (memchr(code, opcode->opcode, size) != NULL)
      errx(1, "opcode %s is not allowed", opcode->name);
  }

  if (mprotect(USER_CODE, PAGE_SIZE, PROT_WRITE) != 0)
    err(1, "mprotect");

  memcpy(USER_CODE, code, size);

  if (mprotect(USER_CODE, PAGE_SIZE, PROT_READ | PROT_EXEC) != 0)
    err(1, "mprotect");
}

static int readall(int fd, void *buf, size_t count)
{
  ssize_t n;
  size_t i;
  char *p;

  p = buf;
  i = count;
  while (i > 0) {
    n = read(fd, p, i);
    if (n == 0) {
      warnx("read failed");
      return -1;
    } else if (n == -1) {
      if (errno == EINTR)
        continue;
      warn("read failed");
      return -1;
    }
    i -= n;
    p += n;

    if (count - i >= MARKER_SIZE) {
      if (memcmp(p - MARKER_SIZE, MARKER, MARKER_SIZE) == 0) {
        printf("[*] received %lu bytes\n", count - i);
        break;
      }
    }
  }

  return count - i;
}

static void go(void)
{
  char buf[PAGE_SIZE];

  memset(buf, '\xcc', sizeof(buf));

  puts("[*] gimme some x86 32-bit code!");

  if (readall(STDIN_FILENO, buf, sizeof(buf)) == -1)
    errx(1, "failed to read code");

  copy_user_code(buf, sizeof(buf));

  puts("[*] let's go...");

  asm volatile (
      "movq     %0, %%rax\n"
      "shlq     $32, %%rax\n"
      "movq     %1, %%rbx\n"
      "orq      %%rbx, %%rax\n"
      "push     %%rax\n"
      "retf\n"
      /* never reached */
      "int $3\n"

      :: "i"(0xf), /* ldt code segment selector. index: 1, table: 1, rpl: 3 */
         "i"(USER_CODE)
      : "rax", "rbx"
                );
}

int main(void)
{
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  setup_userland();
  setup_kernelland();
  check_proc_maps(1);
  install_seccomp();

  go();

  return 0;
}
