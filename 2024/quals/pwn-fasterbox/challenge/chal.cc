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

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <setjmp.h>
#include <sched.h>
#include <syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include <cstring>
#include <iostream>
#include <memory>
#include <utility>
#include <string>
#include <vector>

#include "bpf-helper.h"

constexpr size_t kMaxPayloadSize = 1024 * 1024;

void FAIL(const char* msg) {
  std::cerr << msg << std::endl;
  abort();
}

void CHECK(bool cond, const char* msg) {
  if (!cond) {
    FAIL(msg);
  }
}

void PCHECK(bool cond, const char* msg) {
  int err = errno;
  if (!cond) {
    std::cerr << msg << ": " << strerror(err) << std::endl;
    abort();
  }
}

int memfd_create(const char* name) {
 return syscall(__NR_memfd_create, name, 0);
}

bool WriteToFD(int fd, const char* data, size_t size) {
  while (size > 0) {
    ssize_t result = TEMP_FAILURE_RETRY(write(fd, data, size));
    if (result <= 0) {
      return false;
    }
    size -= result;
    data += result;
  }
  return true;
}

std::string HexToBin(const std::string& hex) {
  CHECK((hex.size() % 2) == 0, "Hex string length not divisible by 2");
  std::string bin;
  bin.resize(hex.size()/2);
  static const char* tab = "0123456789abcdef";
  for (size_t i = 1; i < hex.size(); i += 2) {
    int a = -1;
    int b = -1;
    for (int j = 0; j < 16; ++j) {
      if (tab[j] == hex[i-1]) {
        a = j;
      }
      if (tab[j] == hex[i]) {
        b = j;
      }
    }
    CHECK(a != -1, "Wrong hex value");
    CHECK(b != -1, "Wrong hex value");
    bin[i/2] = a*16 + b;
  }
  return bin;
}

int ReadPayload() {
  std::cout << "Payload (hex encoded) [<1MiB]: ";
  std::string hex_payload;
  char buf[1024];
  for (;;) {
    std::cin.getline(buf, sizeof(buf));
    hex_payload.append(buf, std::cin.gcount());
    if (std::cin.good()) {
      hex_payload.pop_back();
    }
    if ((std::cin.rdstate() & std::ios_base::failbit) == 0) {
      break;
    }
    if (hex_payload.size() >= 2*kMaxPayloadSize) {
      return -1;
    }
    std::cin.clear();
  }
  if (hex_payload.empty()) {
    return -1;
  }
  std::string payload = HexToBin(hex_payload);
  int fd = memfd_create("sandboxee");
  PCHECK(fd != -1, "memfd_create");
  PCHECK(WriteToFD(fd, payload.data(), payload.size()), "Writting payload");
  return fd;
}

int Execveat(int dirfd, const char* pathname, const char* const argv[],
             const char* const envp[], int flags) {
  return syscall(__NR_execveat, static_cast<uintptr_t>(dirfd),
                    reinterpret_cast<uintptr_t>(pathname),
                    reinterpret_cast<uintptr_t>(argv),
                    reinterpret_cast<uintptr_t>(envp),
                    static_cast<uintptr_t>(flags));
}

void RunPayload(int fd) {
  char argv0[] = "sandboxee";
  char* argv[] = {argv0, nullptr};
  char* envp[] = {nullptr};
  Execveat(fd, "", argv, envp, AT_EMPTY_PATH);
  PCHECK(false, "Execveat failed");
}

void ApplySeccomp(sock_filter* code, size_t size) {
  struct sock_fprog prog {
    .len = static_cast<uint16_t>(size), .filter = code,
  };

  CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0,
                 "Denying new privs");
  CHECK(prctl(PR_SET_KEEPCAPS, 0) == 0, "Dropping caps");
  CHECK(
      syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC,
              reinterpret_cast<uintptr_t>(&prog)) == 0,
      "Enabling seccomp filter");
}

void DenySetgroups() {
  int fd = open("/proc/self/setgroups", O_WRONLY);
  PCHECK(fd != -1, "Couldn't open");
  CHECK(dprintf(fd, "deny") >= 0, "Could not write");
  close(fd);
}

void WriteIDMap(const char* name, int id) {
  int fd = open(name, O_WRONLY);
  PCHECK(fd != -1, "Couldn't open");
  CHECK(dprintf(fd, "1000 %d 1", id) >= 0, "Could not write");
  close(fd);
}

void SetupNamespaces(int fd, uid_t uid, gid_t gid) {
  DenySetgroups();
  WriteIDMap("/proc/self/uid_map", uid);
  WriteIDMap("/proc/self/gid_map", gid);
  PCHECK(mkdir("/dev/shm/chroot", 0600) != -1 || errno == EEXIST, "Could not create chroot dir");
  PCHECK(mount("", "/dev/shm/chroot", "tmpfs", 0, "size=2000000") != -1, "Could not mount tmpfs");
  mount("", "/proc", "proc", MS_NODEV | MS_NOEXEC | MS_NOSUID, nullptr);
  PCHECK(mkdir("/dev/shm/chroot/proc", 0600) != -1, "Could not create /proc backing dir");
  CHECK(mount("/proc", "/dev/shm/chroot/proc", "", MS_BIND | MS_REC | MS_NOSUID, nullptr) != -1,
                  "Could not mount a new /proc");
  PCHECK(syscall(__NR_pivot_root, "/dev/shm/chroot", "/dev/shm/chroot") != -1, "Could not pivot_root");
  PCHECK(umount2("/", MNT_DETACH) != -1, "detaching old root");
  PCHECK(chdir("/") == 0,
                  "changing cwd after mntns initialization failed");
}

void RunSandboxee(int fd, uid_t uid, gid_t gid) {
  SetupNamespaces(fd, uid, gid);
  static sock_filter code[] = {
      LOAD_ARCH,
      JNE32(AUDIT_ARCH_X86_64, DENY),

      LOAD_SYSCALL_NR,
      SYSCALL(__NR_execveat, ALLOW),
      SYSCALL(__NR_open, ALLOW),
      SYSCALL(__NR_openat, ALLOW),
      SYSCALL(__NR_lseek, ALLOW),
      SYSCALL(__NR_read, ALLOW),
      SYSCALL(__NR_write, ALLOW),
      SYSCALL(__NR_exit, ALLOW),
      SYSCALL(__NR_exit_group, ALLOW),
      // libc startup
      SYSCALL(__NR_brk, ALLOW),
      SYSCALL(__NR_set_tid_address, ALLOW),
      SYSCALL(__NR_arch_prctl, ALLOW),
      SYSCALL(__NR_set_robust_list, ALLOW),
      SYSCALL(__NR_prlimit64, ALLOW),
      SYSCALL(__NR_readlinkat, ALLOW),
      SYSCALL(__NR_mprotect, ALLOW),
      SYSCALL(__NR_newfstatat, ALLOW),
      SYSCALL(__NR_getrandom, ALLOW),
      SYSCALL(__NR_socketpair, ALLOW),
      SYSCALL(__NR_rseq, ALLOW),
      // Newer syscalls are fine
      BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 400, 1, 0),
      DENY,
//      ERRNO(ENOSYS),
      // Except io_uring
      SYSCALL(__NR_io_uring_setup, DENY),
      SYSCALL(__NR_io_uring_enter, DENY),
      SYSCALL(__NR_io_uring_register, DENY),
      ALLOW,
  };
  ApplySeccomp(code, sizeof(code)/sizeof(code[0]));
  RunPayload(fd);
}

int ChildFunc(void* arg) {
  auto* env_ptr = reinterpret_cast<jmp_buf*>(arg);
  // Restore the old stack.
  longjmp(*env_ptr, 1);
}

pid_t CloneAndJump(int flags, jmp_buf* env_ptr) {
  alignas(128) uint8_t stack_buf[4096];
  // Stack grows down.
  void* stack = stack_buf + sizeof(stack_buf);
  int r = clone(&ChildFunc, stack, flags, env_ptr, nullptr, nullptr, nullptr);
  if (r == -1) {
    FAIL("clone()");
  }
  return r;
}

pid_t ForkWithFlags(int flags) {
  jmp_buf env;
  if (setjmp(env) == 0) {
    return CloneAndJump(flags, &env);
  }

  // Child.
  return 0;
}

pid_t SpawnSandboxee(int fd) {
  uid_t uid = getuid();
  gid_t gid = getgid();
  pid_t pid = ForkWithFlags(SIGCHLD | CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWUTS);
  if (pid == 0) {
    RunSandboxee(fd, uid, gid);
  }
  return pid;
}

void WaitForSandboxee(pid_t pid) {
  int status;
  std::cerr << "Waiting for " << pid << std::endl;
  PCHECK(TEMP_FAILURE_RETRY(waitpid(pid, &status, 0)) != -1, "waitpid failed");
  if (WIFEXITED(status)) {
    std::cerr << "Exited: " << WEXITSTATUS(status) << std::endl;
  } else if (WIFSIGNALED(status)) {
    std::cerr << "Signaled: " << strsignal(WTERMSIG(status)) << std::endl;
  } else {
    std::cerr << "Other: " << status << std::endl;
  }
}

int main() {
  dup2(1, 2);
  std::cout.setf(std::ios::unitbuf);
  std::cerr.setf(std::ios::unitbuf);
  std::vector<pid_t> sandboxees;
  std::cout << "Welcome to Fasterbox executor!" << std::endl;
  std::cout << "You can start up to 10 sandboxees" << std::endl;
  std::cout << "The sandboxees run in parallel" << std::endl;
  std::cout << "Empty payload indicates no more sandboxees" << std::endl;
  for (int i = 0; i < 10; ++i) {
    int fd = ReadPayload();
    if (fd == -1) {
      break;
    }
    pid_t sandboxee = SpawnSandboxee(fd);
    sandboxees.push_back(sandboxee);
  }
  for (pid_t sandboxee : sandboxees) {
    WaitForSandboxee(sandboxee);
  }
}
