// Copyright 2024 Google LLC
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

#include <sys/mount.h>
#include <sys/wait.h>
#include <setjmp.h>
#include <sched.h>
#include <err.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <linux/sched.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <climits>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <vector>

namespace {
pid_t ForkWithFlags(int flags) {
  struct clone_args args;
  memset(&args, 0, sizeof(args));
  args.flags = flags & (~0x7f);
  args.exit_signal = flags & 0x7f;
  return syscall(__NR_clone3, reinterpret_cast<uintptr_t>(&args), sizeof(args));
}

void MySleep(int msec) {
 for (volatile int i = 0; i < msec; ++i)
 for (volatile int j = 0; j < 1000; ++j)
 for (volatile int k = 0; k < 1000; ++k);
}

void MyClose(int fd) {
  syscall(__NR_close_range, fd, fd, 0);
}

int sfds[2];

void MountProc() {
  bool mounted = true;
  bool exhausted = false;
  int last = -1;
  for (size_t i = 0; mounted; ++i) {
    if ((i % 1000) == 0) {
      fprintf(stderr, "Mounted: %zu\r", i);
    }
    int mfd = fsopen("proc", FSOPEN_CLOEXEC);
    if (mfd < 0) {
      warn("Fsopen failed: %zu", i);
      mounted = false;
      continue;
    }
    int r = fsconfig(mfd, FSCONFIG_CMD_CREATE, nullptr, nullptr, 0);
    if (r == -1) {
      warn("Fsconfig failed: %zu", i);
      mounted = errno == EINTR;
      exhausted = errno == EMFILE;
      continue;
    }
    last = mfd;
  }
  if (exhausted) {
    MyClose(last);
  }
  char c = exhausted ? 'A' : ' ';
  write(sfds[1], &c, 1);
  read(sfds[1], &c, 1);
}

}  // namespace

int main() {
  std::vector<pid_t> pids;
  std::vector<int> fds;
  char c = ' ';
  while (c != 'A') {
    fprintf(stderr, "Spawing process\n");
    socketpair(AF_UNIX, SOCK_STREAM, 0, sfds);
    pid_t pid = ForkWithFlags(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWPID | CLONE_NEWNET | SIGCHLD);
    if (pid == -1) {
      err(1, "Fork failed");
    }
    if (pid == 0) {
      for (auto fd : fds) {
        MyClose(fd);
      }
      MountProc();
      return 0;
    }
    MyClose(sfds[1]);
    printf("Spawned %d\n", pid);
    read(sfds[0], &c, 1);
    pids.push_back(pid);
    fds.push_back(sfds[0]);
  }
  fprintf(stderr, "Filling finished\n");
  MySleep(20000);
  fprintf(stderr, "Finishing\n");
  for (size_t i = 0; i < pids.size(); ++i) {
    write(fds[i], &c, 1);
    int status;
    pid_t w = waitpid(pids[i], &status, 0);
    if (w != pids[i]) {
      err(2, "Wait failed %d\n", w);
    }
  }
  return 0;
}
