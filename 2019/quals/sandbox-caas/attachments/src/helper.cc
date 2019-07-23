/*
Copyright 2019 Google LLC

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

#include "helper.h"

#include <bits/local_lim.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <csetjmp>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

// Helper function: Send a file descriptor via an existing communication
// channel.
bool SendFD(int comms_fd, int fd_to_transfer) {
  char fd_msg[CMSG_SPACE(sizeof(int))] = {0};
  cmsghdr *cmsg = reinterpret_cast<cmsghdr *>(fd_msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));

  int *fds = reinterpret_cast<int *>(CMSG_DATA(cmsg));
  fds[0] = fd_to_transfer;

  bool data = true;

  iovec iov;
  iov.iov_base = &data;
  iov.iov_len = sizeof(data);

  msghdr msg;
  msg.msg_name = nullptr;
  msg.msg_namelen = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsg;
  msg.msg_controllen = sizeof(fd_msg);
  msg.msg_flags = 0;

  if (sendmsg(comms_fd, &msg, 0) < 0) {
    _exit(1);
  }
  return true;
}

// Helper function: Receive a file descriptor via an existing communication
// channel.
int ReceiveFD(int comms_fd) {
  char fd_msg[8192];
  cmsghdr *cmsg = reinterpret_cast<cmsghdr *>(fd_msg);

  bool data;
  iovec iov = {&data, sizeof(data)};

  msghdr msg;
  msg.msg_name = nullptr;
  msg.msg_namelen = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsg;
  msg.msg_controllen = sizeof(fd_msg);
  msg.msg_flags = 0;

  if (recvmsg(comms_fd, &msg, 0) < 0) {
    return -1;
  }

  cmsg = CMSG_FIRSTHDR(&msg);
  while (cmsg) {
    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
      if (cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
        continue;
      }
      int *fds = reinterpret_cast<int *>(CMSG_DATA(cmsg));
      return fds[0];
    }
    cmsg = CMSG_NXTHDR(&msg, cmsg);
  }
  return -1;
}

// Will be used later.
bool receive(int fd, std::string *out) {
  uint32_t size;
  if (read(fd, &size, sizeof(size)) < 0) {
    return false;
  }
  out->resize(size);
  if (read(fd, &out->at(0), size) != size) {
    return false;
  }

  return true;
}

bool send(int fd, const std::string &buf) {
  uint32_t size = buf.size();
  if (write(fd, &size, sizeof(size)) < 0 || write(fd, &buf[0], size) < 0) {
    return false;
  }
  return true;
}

bool ReadWholeFile(const char *path, std::string *buf) {
  std::unique_ptr<FILE, decltype(&fclose)> f(fopen(path, "rb"), &fclose);
  if (!f) {
    return false;
  }

  if (fseek(f.get(), 0, SEEK_END)) {
    fprintf(stderr, "fseek failed\n");
    return false;
  }

  size_t filesize = ftell(f.get());
  if (fseek(f.get(), 0, SEEK_SET)) {
    fprintf(stderr, "fseek failed\n");
    return false;
  }

  // Read whole buffer.
  buf->resize(filesize);

  std::string &buf_ = *buf;
  fread(&buf_[0], 1, filesize, f.get());
  return true;
}

bool GetNumberOfThreads(pid_t pid, int *n_threads) {
  char fbuf[128] = {};
  snprintf(fbuf, sizeof(fbuf), "/proc/%d/status", pid);

  std::string buf;
  if (!ReadWholeFile(fbuf, &buf)) {
    return false;
  }
  buf.resize(buf.size() + 1, '\0');

  // Go through line-by-line.
  char *p = &buf[0];
  while (*p) {
    char *c = strstr(p, "\n");
    char *line = p;

    if (!c) {
      break;
    }
    *c = 0;

    if (sscanf(line, "Threads: %d", n_threads) == 1) {
      break;
    }

    p = c + 1;
  }

  return true;
}

int ChildFunc(void *arg) {
  auto *env_ptr = reinterpret_cast<jmp_buf *>(arg);
  // Restore the old stack.
  longjmp(*env_ptr, 1);
}

pid_t CloneAndJump(int flags, jmp_buf *env_ptr) {
  uint8_t stack_buf[PTHREAD_STACK_MIN];
  // Stack grows down.
  void *stack = stack_buf + sizeof(stack_buf);
  int r = clone(&ChildFunc, stack, flags, env_ptr, nullptr, nullptr, nullptr);
  if (r == -1) {
    perror("clone()");
  }
  return r;
}

pid_t ForkWithFlags(int flags) {
  const int unsupported_flags = CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID |
                                CLONE_PARENT_SETTID | CLONE_SETTLS | CLONE_VM;
  if (flags & unsupported_flags) {
    return -1;
  }

  jmp_buf env;
  if (setjmp(env) == 0) {
    return CloneAndJump(flags, &env);
  }

  // Child.
  return 0;
}

std::vector<PageRange> GetStartOfPages() {
  std::vector<PageRange> res;
  std::unique_ptr<FILE, decltype(&fclose)> file(fopen("/proc/self/maps", "r"),
                                                &fclose);
  if (!file.get()) {
    return res;
  }

  uint64_t start, end, off, inode;
  uint32_t major, minor;
  char r, w, x, s;
  while (!feof(file.get())) {
    if (fscanf(file.get(), "%lx-%lx %c%c%c%c %lx %x:%x %lu", &start, &end, &r,
               &w, &x, &s, &off, &major, &minor, &inode)) {
      res.push_back(PageRange{start, end - start});
    }

    while (fgetc(file.get()) != '\n' && !feof(file.get())) {
    }
  }
  return res;
}
