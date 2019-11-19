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
#include <unistd.h>
#include <sys/types.h>
#include <err.h>
#include <stdlib.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <linux/memfd.h>
#include <linux/limits.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <ctype.h>
#include <stdbool.h>

const char BANNER[] = "Procbox: a next-gen sandbox built with namespaces!\n";
const char MENU[] = "\
What would you like to do?\n\
1) Run ELF\n\
2) Exit\n\
> \
";

long check(long res, const char *msg) {
  if (res == -1) {
    err(1, "%s", msg);
  }
  return res;
}

void read_line(char *buf, size_t buf_sz) {
  while (1) {
    if (!buf_sz) {
      errx(1, "newline expected");
    }
    if (read(0, buf, 1) != 1) {
      err(1, "read");
    }
    if (*buf == '\n') {
      *buf = 0;
      return;
    }
    buf++;
    buf_sz--;
  }
}

int read_int() {
  char buf[16] = {0};
  read_line(buf, sizeof(buf));
  return atoi(buf);
}

int execveat(int dirfd, const char *pathname,
                    char *const argv[], char *const envp[],
                    int flags) {
  return syscall(SYS_execveat, dirfd, pathname, argv, envp, flags);
}

int memfd_create(const char *name, unsigned int flags) {
  return syscall(SYS_memfd_create, name, flags);
}

#define MAX_BIN (1024*1024*10)

#define MIN(a, b) (a < b ? a : b)

int read_to_memfd(int fd, unsigned sz) {
  char buf[4096] = {0};
  int memfd = check(memfd_create("x", MFD_CLOEXEC), "memfd_create");
  while (sz) {
    size_t read_sz = check(read(fd, buf, MIN(sizeof(buf), sz)), "read(ELF)");
    if (read_sz == 0) {
      errx(1, "short read");
    }
    if (write(memfd, buf, read_sz) != read_sz) {
      errx(1, "short write");
    }
    sz -= read_sz;
  }
  return memfd;

}

int load_elf() {
  printf("elf len? ");
  fflush(stdout);
  unsigned bin_len = read_int();
  if (bin_len > MAX_BIN) {
    errx(1, "too long");
  }

  printf("data? ");
  fflush(stdout);

  return read_to_memfd(0, bin_len);
}

int init_fd = 0;

void run_elf() {
  int fd = load_elf();
  check(dup2(fd, 137), "dup2");
  pid_t pid = check(fork(), "fork");
  if (!pid) {
    char * const argv[] = {"init", "sandboxee", 0};
    check(execveat(init_fd, "", argv, 0, AT_EMPTY_PATH), "execveat");
  }
  close(fd);
  close(137);
}

void load_init() {
  int sandbox_fd = check(open("sandbox", O_RDONLY), "open(init_fd)");
  unsigned size = check(lseek(sandbox_fd, 0, SEEK_END), "lseek");
  check(lseek(sandbox_fd, 0, SEEK_SET), "lseek");
  init_fd = read_to_memfd(sandbox_fd, size);
  close(sandbox_fd);
}

int main(int argc, char *argv[]) {
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  load_init();
  puts(BANNER);
  while (1) {
    printf(MENU);
    fflush(stdout);
    switch (read_int()) {
      case 1:
        run_elf();
        break;
      default:
        puts("Bye");
        _exit(0);
    }
  }
  return 0;
}
