/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <emmintrin.h>

int check(int res, const char *msg) {
  if (res == -1) {
    err(1, "%s", msg);
  }
  return res;
}

unsigned long readme;
char flag[25] = {0};

void readn(int fd, char *buf, size_t len) {
  while (len > 0) {
    ssize_t read_cnt = check(read(fd, buf, len), "read");
    if (!read_cnt) {
      errx(1, "EOF");
    }
    len -= read_cnt;
    buf += read_cnt;
  }
}

void read_flag() {
  int fd = check(open("flag", O_RDONLY), "open(flag)");
  readn(fd, flag, sizeof(flag)-1);
  close(fd);

  puts("flag loaded");
}

void victim() {
  read_flag();
  while (1) {
    for (int i = 0; i < 10000000; i++) {
      _mm_prefetch(&readme, _MM_HINT_NTA);
      _mm_mfence();
      _mm_clflush(&readme);
      _mm_mfence();
    }
    int wstatus;
    if(check(waitpid(-1, &wstatus, WNOHANG), "waitpid")) {
      puts("child exited, bye!");
      exit(0);
    }
  }
}

void setup_seccomp() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  int ret = 0;
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  ret |= seccomp_load(ctx);
  if (ret) {
    errx(1, "seccomp failed");
  }
}

int main() {
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  if (check(fork(), "fork")) {
    victim();
    return 0;
  }

  puts("sclen (4B LE)||sc");

  unsigned sc_len = 0;
  readn(STDIN_FILENO, (char*)&sc_len, sizeof(sc_len));
  size_t aligned_sz = sc_len;
  aligned_sz += 4096;
  aligned_sz &= ~0xfff;

  char *sc = mmap(0, aligned_sz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
  if (sc == MAP_FAILED) {
    err(1, "mmap");
  }

  void *probe = mmap(0, 256*(4096/8), PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

  // fun fact: SECCOMP_MODE_STRICT disables RDTSC
  //check(prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT), "prctl(seccomp)");
  setup_seccomp();

  readn(STDIN_FILENO, sc, sc_len);

  ((void (*)(void *)) sc)(probe);

  return 0;
}
