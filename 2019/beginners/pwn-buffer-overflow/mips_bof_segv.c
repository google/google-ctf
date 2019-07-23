/**
 * Copyright 2019 Google LLC
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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/**
 * bufferflow triggering segfault  - MIPS binary, compile with:
 * mipsel-linux-gnu-gcc /tmp/mips_bof_segv.c -o /tmp/bof -static -fno-stack-protector -z execstack -ffunction-sections
 *
 * Registers a SIGSEGV signal handler and which outputs the 1st flag on a crash.
 * Controlling the buffer overflow to call local_flag() func displays the second
 * flag. Note - it's possible to get both flags in the same crash (depending
 * input buffer).
 * hint for players: - address of local_flag func
 * (gdb) info address local_flag
 * Symbol "local_flag" is at 0x00400840 in a file compiled without debugging.
 */

static void print_file(const char* file) {
  int fd = open(file, O_RDONLY);
  if (fd == -1) {
    puts("could not open flag");
    exit(1);
  }
  char c;
  while (read(fd, &c, 1) == 1) {
    write(1, &c, 1);
  }
  close(fd);
}

static void local_flag() {
  print_file("flag1");
  exit(0);
}

static void write_out(int signo) {
  printf("segfault detected! ***CRASH***");
  print_file("flag0");
  exit(0);
}

int main() {
  if (signal(SIGSEGV, write_out) == SIG_ERR) {
    printf("An error occurred setting a signal handler.");
    return -1;
  }
  int c = 1;
  char input[256];
  puts("Cauliflower systems never crash >>");
  scanf("%s", input);
  if(c == 0) {
    local_flag();
  }
  return 0;
}
