/*
 * Copyright 2020 Google LLC
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
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>

int main() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  // Launch the server
  pid_t pid = fork();
  if (pid < 0) {
    err(1, "fork");
  }
  if (pid == 0) {
    int fd = open("/dev/null", O_RDWR);
    for (int i = 0; i <= 2; ++i) {
      if (dup2(fd, i) < 0) {
        err(1, "dup2");
      }
    }
    close(fd);
    execl("/root/echo_srv", "echo_srv", NULL);
    err(1, "exec(echo_srv)");
  }
  // Exec launcher
  pid_t launcher_pid = fork();
  if (launcher_pid < 0) {
    err(1, "fork");
  }
  if (launcher_pid == 0) {
    // Drop privs
    if (setresgid(1339, 1339, 1339) != 0) {
      err(1, "setresgid");
    }
    if (setresuid(1339, 1339, 1339) != 0) {
      err(1, "setresgid");
    }
    cap_t caps = cap_init();
    if (cap_set_proc(caps) != 0) {
      err(1, "cap_set_proc");
    }
    if (cap_free(caps) != 0) {
      err(1, "cap_free");
    }
    execl("/home/user/launcher", "launcher", NULL);
    err(1, "exec(launcher)");
  }
  int status;
  if (TEMP_FAILURE_RETRY(waitpid(launcher_pid, &status, 0)) != launcher_pid) {
    err(1, "waitpid");
  }
  kill(pid, SIGKILL);
  return 0;
}
