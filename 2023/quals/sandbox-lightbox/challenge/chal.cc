// Copyright 2023 Google LLC
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

#include <cstring>
#include <iostream>
#include <memory>
#include <utility>
#include <string>

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

void* ReadPayload() {
  void* mapping = mmap(0, kMaxPayloadSize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  PCHECK(mapping != MAP_FAILED, "mmap failed");
  std::cout << "Payload size in bytes [<1MiB]: ";
  size_t sz = 0;
  std::cin >> sz;
  std::cin.clear();
  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
  while (sz > kMaxPayloadSize) {
    std::cout << "Payload too big. Try again!" << std::endl;
    std::cout << "Payload size in bytes [<1MiB]: ";
    std::cin >> sz;
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
  }
  std::cin.read(reinterpret_cast<char*>(mapping), sz);
  return mapping;
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

void CloseFds() {
  // Make sure all FDs are closed
  for (int i = 0; i < 4096; ++i) {
    close(i);
  }
}

void RunInitProcess(pid_t main_pid) {
  CloseFds();
  static sock_filter code[] = {
      LOAD_ARCH,
      JNE32(AUDIT_ARCH_X86_64, DENY),

      LOAD_SYSCALL_NR,
      SYSCALL(__NR_waitid, ALLOW),
      SYSCALL(__NR_exit, ALLOW),
      DENY
  };

  ApplySeccomp(code, sizeof(code)/sizeof(code[0]));

  siginfo_t info;
  // Reap children.
  for (;;) {
    int rv = TEMP_FAILURE_RETRY(waitid(P_ALL, -1, &info, WEXITED | __WALL));
    if (rv != 0) {
      _exit(1);
    }
    if (info.si_pid == main_pid) {
      _exit(0);
    }
  }
}

void RunPayload(void* payload) {
  reinterpret_cast<void(*)()>(payload)();
  abort();
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

void SetupNamespaces(uid_t uid, gid_t gid) {
  DenySetgroups();
  WriteIDMap("/proc/self/uid_map", uid);
  WriteIDMap("/proc/self/gid_map", gid);
  PCHECK(mkdir("/tmp/chroot", 0600) != -1 || errno == EEXIST, "Could not create chroot dir");
  PCHECK(mount("", "/tmp/chroot", "tmpfs", 0, "size=2000000") != -1, "Could not mount tmpfs");
  PCHECK(mkdir("/tmp/chroot/proc", 0600) != -1, "Could not create /proc backing dir");
  CHECK(mount("", "/tmp/chroot/proc", "proc", MS_NODEV | MS_NOEXEC | MS_NOSUID,
                        nullptr) != -1,
                  "Could not mount a new /proc");
  PCHECK(syscall(__NR_pivot_root, "/tmp/chroot", "/tmp/chroot") != -1, "Could not pivot_root");
  PCHECK(umount2("/", MNT_DETACH) != -1, "detaching old root");
  PCHECK(chdir("/") == 0,
                  "changing cwd after mntns initialization failed");
}

void RunSandboxee(void* payload, uid_t uid, gid_t gid) {
  SetupNamespaces(uid, gid);
  pid_t pid = fork();
  if  (pid != 0) {
    RunInitProcess(pid);
  }
  static sock_filter code[] = {
      LOAD_ARCH,
      JNE32(AUDIT_ARCH_X86_64, DENY),

      LOAD_SYSCALL_NR,
      SYSCALL(__NR_open, ALLOW),
      SYSCALL(__NR_openat, ALLOW),
      SYSCALL(__NR_lseek, ALLOW),
      SYSCALL(__NR_read, ALLOW),
      SYSCALL(__NR_write, ALLOW),
      SYSCALL(__NR_exit, ALLOW),
      DENY
  };
  ApplySeccomp(code, sizeof(code)/sizeof(code[0]));
  RunPayload(payload);
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

pid_t SpawnSandboxee(void* payload) {
  uid_t uid = getuid();
  gid_t gid = getgid();
  pid_t pid = ForkWithFlags(SIGCHLD | CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWUTS);
  if (pid == 0) {
    RunSandboxee(payload, uid, gid);
  }
  return pid;
}

void WriteFlagToShMem() {
  constexpr int kMapSize = 128;
  int id = shmget(0xf7a6, kMapSize, IPC_CREAT | 0600);
  PCHECK(id != -1, "Creating shared memory");
  void* map = shmat(id, nullptr, 0);
  PCHECK(map != reinterpret_cast<void*>(-1), "Attaching shared memory");
  int fd = open("/home/user/flag", O_RDONLY);
  PCHECK(fd != -1, "Opening flag");
  int r = read(fd, map, kMapSize);
  PCHECK(r != -1, "Reading flag");
  PCHECK(close(fd) == 0, "Closing flag");
  PCHECK(shmdt(map) != -1, "Detaching mapping");
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
  std::cout.setf(std::ios::unitbuf);
  std::cerr.setf(std::ios::unitbuf);
  WriteFlagToShMem();
  std::cout << "Welcome to Lightbox executor!" << std::endl;
  void* payload = ReadPayload();
  pid_t sandboxee = SpawnSandboxee(payload);
  WaitForSandboxee(sandboxee);
}

