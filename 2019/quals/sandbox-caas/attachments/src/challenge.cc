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

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

#include <cstddef>
#include <iostream>
#include <string>
#include <optional>
#include <string_view>

#include "helper.h"
#include "rpc.h"

namespace Unmapper {
#include "unmapper.h"
}

namespace {

pid_t sigalrm_child_pid = 0;
void kill_on_timeout(int sig) {
  if (sig == SIGALRM) {
    kill(sigalrm_child_pid, SIGKILL);
  }
}

const std::basic_string_view<uint8_t> GetInitAssembly() {
  return std::basic_string_view<uint8_t>{Unmapper::unmapper, Unmapper::unmapper_len};
}

}  // namespace

void handle_connection(std::optional<int> fd) {
  // To set up uid/gid map later.
  const int uid = getuid();
  const int gid = getgid();

  // To wipe out unnecessary pages later.
  auto pages = GetStartOfPages();

  const auto init_assembly = GetInitAssembly();

  if (pages.empty()) {
    fprintf(stderr, "Could not get details about used pages\n");
    return;
  }
  // EOF marker for our unmapping code.
  pages.push_back(PageRange{0, 0});

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
    perror("socketpair");
    return;
  }

  pid_t child_pid =
      ForkWithFlags(CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET |
                    CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWCGROUP | SIGCHLD);

  if (child_pid == -1) {
    perror("fork()");
  } else if (child_pid == 0) {
    // Child process
    close(sv[0]);

    // Set UID/GID map
    {
      char uid_buf[64];
      int f;
      {
        f = open("/proc/self/setgroups", O_WRONLY);
        if (f < 0 || write(f, "deny", 4) != 4) {
          err(1, "setgroups");
        }
        close(f);
      }
      {
        sprintf(uid_buf, "0 %d 1", uid);
        f = open("/proc/self/uid_map", O_WRONLY);
        if (f < 0 || write(f, uid_buf, strlen(uid_buf)) !=
                         static_cast<ssize_t>(strlen(uid_buf))) {
          err(1, "uid_map");
        }
        close(f);
      }
      {
        sprintf(uid_buf, "0 %d 1", gid);
        f = open("/proc/self/gid_map", O_WRONLY);
        if (f < 0 || write(f, uid_buf, strlen(uid_buf)) !=
                         static_cast<ssize_t>(strlen(uid_buf))) {
          err(1, "gid_map");
        }
        close(f);
      }
    }

    // Set up FS namespace.
    if (mkdir("/tmp/.challenge", 0700) < 0 && errno != EEXIST) {
      err(1, "mkdir");
    }

    if (mount("none", "/tmp/.challenge", "tmpfs", 0, nullptr) < 0) {
      err(1, "mount");
    }

    // Enter the new FS namespace.
    if (syscall(__NR_pivot_root, "/tmp/.challenge", "/tmp/.challenge") < 0) {
      err(1, "pivot_root");
    }
    if (umount2("/", MNT_DETACH) < 0) {
      err(1, "umount2(/)");
    }
    chdir("/");

    // Drop capabilities.
    auto caps = cap_init();
    if (cap_set_proc(caps) < 0) {
      err(1, "cap_set_proc()");
    }
    cap_free(caps);

    // Namespace jailed process.
    if (fd.has_value()) {
      dup2(fd.value(), STDIN_FILENO);
      dup2(fd.value(), STDOUT_FILENO);
      dup2(fd.value(), STDERR_FILENO);
      close(fd.value());
    }

    // Move our communication FD to a well known #.
    dup2(sv[1], 100);
    close(sv[1]);
    sv[1] = 100;

    static constexpr char banner[] = {
        "Welcome to the awesome cloud computation engine!\n"
        "We will run your application* for you\n\n"
        " Format: <u16 assembly length> <x64 assembly>\n\n"
        "*) Some restrictions apply\n"};
    if (TEMP_FAILURE_RETRY(write(STDOUT_FILENO, banner, sizeof(banner) - 1)) !=
        sizeof(banner) - 1) {
      _exit(1);
    }
    // Receive shellcode from stdin and exevute.
    void *scode = mmap(nullptr, 0x1000, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (!scode) {
      _exit(1);
    }

    {
      uint16_t pkg_size;
      if (TEMP_FAILURE_RETRY(read(STDIN_FILENO, &pkg_size, sizeof(uint16_t))) !=
          sizeof(uint16_t)) {
        _exit(1);
      }

      if (pkg_size > 0x800) {
        fprintf(stderr, "Too large, sorry!\n");
        _exit(1);
      }

      memcpy(scode, init_assembly.data(), init_assembly.size());

      if (TEMP_FAILURE_RETRY(read(
              STDIN_FILENO, (void *)((uintptr_t)scode + init_assembly.size()),
              pkg_size)) != pkg_size) {
        _exit(1);
      }

      // Mark code executable.
      if (mprotect(scode, 0x1000, PROT_READ | PROT_EXEC)) {
        err(1, "mprotect");
      }

      // One more page for the memory ranges.
      void *param = mmap(nullptr, 0x1000, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
      memcpy(param, pages.data(), pages.size() * sizeof(PageRange));

      // Apply limits.
      {
        // 1 second of cputime should be plenty.
        rlimit64 rlimit_cpu_limit{
            .rlim_cur = 1,
            .rlim_max = 1,
        };
        if (setrlimit64(RLIMIT_CPU, &rlimit_cpu_limit)) {
          err(1, "rlimit_cpu");
        }

        rlimit64 rlimit_core_limit{
            .rlim_cur = 0,
            .rlim_max = 0,
        };
        if (setrlimit64(RLIMIT_CORE, &rlimit_core_limit)) {
          err(1, "rlimit_core");
        }
      }

      // Apply seccomp policy.
      static uint8_t seccomp_policy[] = {
          0x20, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00,
          0x3c, 0x3e, 0x00, 0x00, 0xc0, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x35, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x40, 0x15,
          0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x37, 0x00,
          0x01, 0x00, 0x00, 0x00, 0x15, 0x00, 0x36, 0x00, 0x03, 0x00, 0x00,
          0x00, 0x15, 0x00, 0x35, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x15, 0x00,
          0x34, 0x00, 0x18, 0x00, 0x00, 0x00, 0x15, 0x00, 0x33, 0x00, 0x20,
          0x00, 0x00, 0x00, 0x15, 0x00, 0x32, 0x00, 0x21, 0x00, 0x00, 0x00,
          0x15, 0x00, 0x31, 0x00, 0x23, 0x00, 0x00, 0x00, 0x15, 0x00, 0x30,
          0x00, 0x2a, 0x00, 0x00, 0x00, 0x15, 0x00, 0x2f, 0x00, 0x2b, 0x00,
          0x00, 0x00, 0x15, 0x00, 0x2e, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x15,
          0x00, 0x2d, 0x00, 0x31, 0x00, 0x00, 0x00, 0x15, 0x00, 0x2c, 0x00,
          0x3c, 0x00, 0x00, 0x00, 0x15, 0x00, 0x2b, 0x00, 0xe7, 0x00, 0x00,
          0x00, 0x15, 0x00, 0x00, 0x04, 0x38, 0x00, 0x00, 0x00, 0x20, 0x00,
          0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x29, 0x00,
          0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
          0x15, 0x00, 0x26, 0x27, 0x00, 0x09, 0x01, 0x00, 0x15, 0x00, 0x00,
          0x0c, 0x29, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x14, 0x00,
          0x00, 0x00, 0x15, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x20,
          0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x22,
          0x02, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00,
          0x00, 0x15, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
          0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x1e, 0x01,
          0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
          0x15, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
          0x00, 0x20, 0x00, 0x00, 0x00, 0x15, 0x00, 0x19, 0x1a, 0x00, 0x00,
          0x00, 0x00, 0x15, 0x00, 0x00, 0x19, 0x09, 0x00, 0x00, 0x00, 0x20,
          0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x17,
          0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
          0x00, 0x15, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
          0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x13, 0x00,
          0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
          0x15, 0x00, 0x00, 0x11, 0x00, 0x10, 0x00, 0x00, 0x20, 0x00, 0x00,
          0x00, 0x24, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x0f, 0x00, 0x00,
          0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x15,
          0x00, 0x00, 0x0d, 0x03, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
          0x2c, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
          0x00, 0x20, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x15, 0x00,
          0x00, 0x09, 0x22, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x34,
          0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00,
          0x20, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00,
          0x05, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x3c, 0x00,
          0x00, 0x00, 0x15, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x20,
          0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x01,
          0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
          0x7f, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
      if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        err(1, "prctl");
      }

      // Close all FDs except for STD{IN,OUT,ERR}.
      for (int i = 0; i < 1024; i++) {
        if (i < 3 || i == 100) continue;
        close(i);
      }

      struct sock_fprog seccomp_prog {
        .len = sizeof(seccomp_policy) / 8,
        .filter = reinterpret_cast<struct sock_filter *>(seccomp_policy),
      };
      if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0,
                  reinterpret_cast<uintptr_t>(&seccomp_prog)) != 0) {
        err(1, "seccomp");
      }

      auto func = (void (*)(void *))scode;
      func(param);
      _exit(0);
    }
  } else {
    // Parent
    if (ptrace(PTRACE_SEIZE, child_pid, 0, PTRACE_O_EXITKILL) == 0) {
      int comms_fd = sv[0];
      close(sv[1]);
      if (fd.has_value()) {
        close(fd.value());
      }

      sigalrm_child_pid = child_pid;
      signal(SIGALRM, kill_on_timeout);
      alarm(2);
      RPC::Server(child_pid, comms_fd);
    } else {
      perror("ptrace(PTRACE_SEIZE, PTRACE_O_EXITKILL)");
    }
    kill(child_pid, SIGKILL);
    while (TEMP_FAILURE_RETRY(waitpid(child_pid, nullptr, 0)) != -1 &&
           errno != ECHILD) {
    }
    signal(SIGALRM, SIG_DFL);
  }
}

pid_t FlagServer() {
  std::string flag;
  if (!ReadWholeFile("flag", &flag)) {
    fprintf(stderr, "No flag file found\n");
    exit(1);
  }

  pid_t p = fork();
  if (p == -1) {
    perror("fork()");
    abort();
  } else if (p) {
    // Nope, you don't have to look in the memory for the flag.
    for (size_t i = 0; i < flag.length(); i++) {
      flag[i] = 0;
    }
    return p;
  }

  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    err(1, "socket()");
  }

  {
    int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
      err(1, "setsockopt(SO_REUSEADDR)");
    }
  }

  // Listen to localhost only.
  struct sockaddr_in addr = {};
  addr.sin_addr.s_addr = htonl(0x7f000001L);
  addr.sin_port = htons(6666);
  addr.sin_family = AF_INET;

  if (bind(fd, (struct sockaddr *)&addr, sizeof(sockaddr_in)) < 0) {
    err(1, "bind()");
  }

  if (listen(fd, 1) < 0) {
    err(1, "listen()");
  }

  while (true) {
    FDCloser client{accept(fd, 0, 0)};
    if (client.get() < 0) {
      perror("accept()");
      break;
    }

    write(client.get(), flag.c_str(), flag.length());
  }

  abort();
}


pid_t MetadataServer() {
  pid_t p = fork();
  if (p == -1) {
    perror("fork()");
    abort();
  } else if (p) {
    return p;
  }

  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    err(1, "socket()");
  }

  {
    int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
      err(1, "setsockopt(SO_REUSEADDR)");
    }
  }

  // Listen to localhost only.
  struct sockaddr_in addr = {};
  addr.sin_addr.s_addr = htonl(0x7f000001L);
  addr.sin_port = htons(8080);
  addr.sin_family = AF_INET;

  if (bind(fd, (struct sockaddr *)&addr, sizeof(sockaddr_in)) < 0) {
    err(1, "bind()");
  }

  if (listen(fd, 128) < 0) {
    err(1, "listen()");
  }

  while (true) {
    FDCloser client{accept(fd, 0, 0)};
    if (client.get() < 0) {
      perror("accept()");
      break;
    }

    write(client.get(), "Not implemented\n", 16);
  }

  abort();
}

int main() {
  pid_t flagserver_pid = FlagServer();
  if (flagserver_pid == -1) {
    return 1;
  }

  pid_t metadata_pid = MetadataServer();
  if (metadata_pid == -1) {
    return 1;
  }

#ifdef NETWORK_SERVICE
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    perror("socket()");
    return 1;
  }

  {
    int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
      perror("setsockopt(SO_REUSEADDR)");
      close(fd);
      return 1;
    }
  }

  struct sockaddr_in addr = {};
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(1234);
  addr.sin_family = AF_INET;

  if (bind(fd, (struct sockaddr *)&addr, sizeof(sockaddr_in)) < 0) {
    perror("bind()");
    close(fd);
    return 1;
  }

  if (listen(fd, 1) < 0) {
    perror("listen()");
    close(fd);
    return 1;
  }

  std::cout << "Accepting connections" << std::endl;
  while (true) {
    FDCloser client{accept(fd, 0, 0)};
    if (client.get() < 0) {
      perror("accept (client)()");
      break;
    }

    pid_t p = fork();
    if (p == -1) {
      perror("fork");
      break;
    } else if (p) {
      close(client.release());
      TEMP_FAILURE_RETRY(waitpid(p, nullptr, 0));
    } else {
      close(fd);
      handle_connection(client.get());
      _exit(0);
    }
  }
  close(fd);
#else
  // Service on STDIN/STDOUT.
  setbuf(stdout, 0);
  setbuf(stderr, 0);
  handle_connection(std::nullopt);
#endif
  kill(flagserver_pid, SIGTERM);
  kill(metadata_pid, SIGTERM);
  return 0;
}
