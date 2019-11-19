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
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h>

#define MAX_ELF_SIZE 1024*1024*30
#define MIN(a, b) (a < b ? a : b)

char line[256];

void read_line() {
  int size;
  for (size = 0; size < sizeof(line)-1; ++size) {
    char c;
    int r = read(0, &c, 1);
    if (r <= 0) {
      break;
    }
    if (c == '\n') {
      break;
    }
    line[size] = c;
  }
  line[size] = '\0';
}

int load_elf(void) {
  read_line();
  size_t size = atoi(line);
  if (size > MAX_ELF_SIZE) {
    puts("too big");
    return -1;
  }
  int exe = memfd_create("solution_exe", MFD_ALLOW_SEALING | MFD_CLOEXEC);
  if (exe < 0) {
    puts("internal error");
    return -1;
  }
  char buf[2048];
  while (size) {
    ssize_t read_sz = read(0, buf, MIN(sizeof(buf), size));
    if (read_sz <= 0) {
      puts("error on read");
      return -1;
    }
    if (write(exe, buf, read_sz) != read_sz) {
      puts("internal error");
      return -1;
    }
    size -= read_sz;
  }
  if (fcntl(exe, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SHRINK
    | F_SEAL_GROW | F_SEAL_SEAL)) {
    puts("internal error");
    return -1;
  }
  return exe;
}

int execute_helper() {
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
    puts("internal error");
    return -1;
  }
  pid_t pid = fork();
  if (pid < 0) {
    puts("internal error");
    return -1;
  }
  if (pid == 0) {
    close(sv[1]);
    dup2(sv[0], STDIN_FILENO);
    dup2(sv[0], STDOUT_FILENO);
    close(sv[0]);
    execl("/root/helper", "/root/helper", NULL);
    abort();
  }
  close(sv[0]);
  return sv[1];
}

pid_t execute_in_jail(int exe, int comms) {
  char path[PATH_MAX];
  sprintf(path, "/proc/%d/fd/%d", getpid(), exe);
  pid_t pid = fork();
  if (pid == 0) {
    if (chown("/tmp/sboxchroot", 1339, 1339) != 0) {
      perror("chown");
      abort();
    }
    dup2(comms, 37);
    char* args[] = {
      "/root/nsjail",
      "-Q",
      "--pass_fd", "37",
      "-u", "1000:1339",
      "-g", "1000:1339",
      "--rw",
      "--chroot", "/tmp/sboxchroot",
      "--proc_rw",
      "--execute_fd",
      "--disable_rlimits",
      "--",
      path,
      NULL,
    };
    execv("/root/nsjail", args);
    abort();
  }
  close(comms);
  return pid;
}

int main(int argc, char* argv[]) {
  int exe = load_elf();
  if (exe < 0) {
    return -1;
  }
  puts("ok");
  int comms = execute_helper();
  if (comms < 0) {
    return -1;
  }
  pid_t child = execute_in_jail(exe, comms);
  if (child < 0) {
    return -1;
  }
  puts("started");
  int status;
  if (waitpid(child, &status, WUNTRACED) != child) {
    puts("internal error");
    return -1;
  }
  if (WIFEXITED(status)) {
    puts("exited");
    if (WEXITSTATUS(status) != 0) {
      return -1;
    }
  } else {
    kill(child, SIGKILL);
    puts("killed");
  }
  return 0;
}
