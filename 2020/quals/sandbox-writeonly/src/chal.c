/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 */
#include <err.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <seccomp.h>
#include <sys/mman.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>

long check(long res, const char *msg) {
  if (res == -1) {
    err(1, "%s", msg);
  }
  return res;
}

void setup_seccomp() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  int ret = 0;
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_yield), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vfork), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchdir), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  ret |= seccomp_load(ctx);
  if (ret) {
    exit(1);
  }
}

typedef void (*void_fn)(void);

void read_line(char *buf, size_t buf_len) {
  while (buf_len) {
    ssize_t read_cnt = read(STDIN_FILENO, buf, 1);
    if (read_cnt <= 0) {
      err(1, "read_line");
    }
    if (buf[0] == '\n') {
      buf[0] = 0;
      return;
    }
    buf++;
    buf_len--;
  }
  errx(1, "no newline in input found");
}

unsigned long read_ulong() {
  char buf[32] = "";
  read_line(buf, sizeof(buf));
  unsigned long ret = strtoul(buf, NULL, 10);
  if (ret == ULONG_MAX) {
    err(1, "strtoul");
  }
  return ret;
}

void read_all(int fd, char *buf, size_t len) {
  while (len) {
    ssize_t num_read = read(fd, buf, len);
    if (num_read <= 0) {
      err(1, "read");
    }
    len -= (size_t) num_read;
    buf += (size_t) num_read;
  }
}

void_fn read_shellcode() {
  printf("shellcode length? ");
  fflush(stdout);
  unsigned long sc_len = read_ulong();
  if (sc_len == 0 || sc_len > 4096) {
    errx(1, "invalid size (max 4096): %lu", sc_len);
  }
  printf("reading %lu bytes of shellcode. ", sc_len);
  fflush(stdout);
  void* sc = mmap(0, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
  if (sc == MAP_FAILED) {
    err(1, "mmap");
  }
  read_all(STDIN_FILENO, sc, sc_len);
  return (void_fn) sc;
}

void check_flag() {
  while (1) {
    char buf[4] = "";
    int fd = check(open("/home/user/flag", O_RDONLY), "open(flag)");
    if (read(fd, buf, sizeof(buf)) != sizeof(buf)) {
      err(1, "read(flag)");
    }
    close(fd);
    if (memcmp(buf, "CTF{", sizeof(buf)) != 0) {
      errx(1, "flag doesn't start with CTF{");
    }
    sleep(1);
  }
}

int main(int argc, char *argv[]) {
  pid_t pid = check(fork(), "fork");
  if (!pid) {
    while (1) {
      check_flag();
    }
    return 0;
  }

  printf("[DEBUG] child pid: %d\n", pid);
  void_fn sc = read_shellcode();
  setup_seccomp();
  sc();

  return 0;
}
