/*
 * Copyright 2018 Google LLC
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
#include "util.h"

#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <err.h>

pid_t spawn_binary(int broker_fd, int exec_fd) {
  pid_t pid = check(fork(), "fork(spawn binary)");
  if (pid == 0) {
    load_libraries(broker_fd, exec_fd);
    char * const argv[] = {"foobar", NULL};
    syscall(SYS_execveat, exec_fd, "", argv, NULL, AT_EMPTY_PATH);
    err(1, "execveat(foobar)");
  }
  return pid;
}

void waitfor(pid_t pid) {
  int wstatus = 0;
  while (1) {
    check(waitpid(pid, &wstatus, WUNTRACED), "waitpid");
    if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
      return;
    }
  }
}

int main(int argc, char *argv[]) {
  int broker_fd = BROKER_FD;
  int sandbox_fd = SANDBOX_FD;

  make_cloexec(broker_fd);
  make_cloexec(sandbox_fd);

  check(prctl(PR_SET_DUMPABLE, 0), "prctl(PR_SET_DUMPABLE, 0)");

  while (1) {
    int exec_fd = recv_fd(sandbox_fd);
    pid_t pid = spawn_binary(broker_fd, exec_fd);
    waitfor(pid);
    send_str(sandbox_fd, "OK");
  }

  return 0;
}

