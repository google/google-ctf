/*
Copyright 2018 Google LLC

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

#define _GNU_SOURCE
#include <sched.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <linux/memfd.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>
#include <regex.h>
#include <linux/random.h>

#include "util.h"

#define SHARED_DIR "/tmp/shared"
#define SHARED_PATH_RE "/|(^[.][.]$)|(^[.]$)"
#define STACK_SIZE (0x8000)

void get_socketpair(int sv[]) {
  check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), "socketpair");
  make_cloexec(sv[0]);
  make_cloexec(sv[1]);
}

static regex_t shared_path_preg;

void init() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  if (regcomp(&shared_path_preg, SHARED_PATH_RE, REG_EXTENDED) != 0) {
    err(1, "regcomp");
  }
  if (mkdir(SHARED_DIR, 0700) == -1 && errno != EEXIST) {
    err(1, "mkdir(SHARED)");
  }
}

int getrandom(void *buf, size_t buflen, unsigned int flags) {
  return syscall(SYS_getrandom, buf, buflen, flags);
}

void * get_rnd_addr() {
  long long unsigned rnd_addr = 0;
  if (getrandom(&rnd_addr, sizeof(rnd_addr), 0) != sizeof(rnd_addr)) {
    err(1, "getrandom");
  }
  rnd_addr &= 0x00007ffffffff000llu;
  return (void*)rnd_addr;
}

int run_process(void (*fn)(int, void*), void* arg, int *pid) {
  int sv[2] = {0};
  get_socketpair(sv);

  int new_pid = check(fork(), "fork()");
  if (new_pid != 0) {
    check(close(sv[0]), "close(sv[0])");
    if (pid) {
      *pid = new_pid;
    }
    return sv[1];
  }
  check(close(sv[1]), "close(sv[1])");

  // Setup a secure stack that always returns to a page filled with hlt
  // instructions for defense in depth.
  void *exit_addr = get_rnd_addr();
  char * exit_fn = mmap(exit_addr, 4096, PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
  if (exit_fn != exit_addr) {
    err(1, "mmap");
  }
  memset(exit_fn, 0xf4, 4096);
  check(mprotect(exit_fn, 4096, PROT_READ|PROT_EXEC), "mprotect");

  void *stack_addr = get_rnd_addr();
  char *new_stack = mmap(stack_addr, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_GROWSDOWN, -1, 0);
  if (new_stack != stack_addr) {
    err(1, "mmap");
  }
  new_stack += 4096-8;
  *(void **) new_stack = exit_addr;
  asm("movq %[stack], %%rsp\t\n"
      "movl  %[fd], %%edi\t\n"
      "movq  %[arg], %%rsi\t\n"
      "movq  %[fn], %%rax\t\n"
      "jmp *%%rax"
      :
      : [stack] "r" (new_stack), [fd] "r" (sv[0]), [arg] "r" (arg), [fn] "r" (fn)
      : "rsp", "rdi", "rsi", "rax");

  _exit(1);
}

void file_broker(int fd, void *unused) {
  int val = 1;
  check(setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &val, sizeof(val)), "setsockopt(SO_PASSCRED)");

  while (1) {
    int sandboxee_pid = recv_pid(fd);

    char proc_cwd[PATH_MAX];
    snprintf(proc_cwd, PATH_MAX, "/proc/%d/cwd", sandboxee_pid);
    char proc_root[PATH_MAX];
    snprintf(proc_root, PATH_MAX, "/proc/%d/root", sandboxee_pid);

    unsigned long long mode = read_ull(fd);
    if (mode == EXIT) {
      break;
    }

    char *path = read_str(fd);
    // Shared path is easy to check, block ".*/.*", "." and ".."
    if (regexec(&shared_path_preg, path, 0, NULL, 0) != REG_NOMATCH) {
      err(1, "hax attempt (path)");
    }

    char shared_path[PATH_MAX];
    snprintf(shared_path, sizeof(shared_path), "%s/%s", SHARED_DIR, path);

    if (mode == GET_FILE) {
      char out_path_abs[PATH_MAX];
      char *out_path_rel = read_str(fd);
      char *out_path = out_path_rel;

      // checking the out_path is more complicated as it will be relative to the
      // user's mount namespace.
      if (out_path_rel[0] != '/') {
        // First, if the outpath is relative, make it absolute.
        ssize_t cwd_len = readlink(proc_cwd, out_path_abs, sizeof(out_path_abs)-1);
        out_path_abs[cwd_len] = 0;

        if (out_path_abs[cwd_len-1] != '/') {
          // We left space for the / in the readlink call
          strncat(out_path_abs, "/", 1);
        }
        strncat(out_path_abs, out_path_rel, sizeof(out_path_abs)-cwd_len-1);
        out_path = out_path_abs;
      }

      // This function will make sure that we don't follow any symlinks that
      // point outside of the task's root directory.
      int write_fd = create_under_root(proc_root, out_path);
      int read_fd = check(open(shared_path, O_RDONLY | O_CLOEXEC | O_EXCL | O_NOFOLLOW), "open(user file)");

      copy_fd(read_fd, write_fd);

      check(close(write_fd), "close");
      check(close(read_fd), "close");

      free(out_path_rel);
    } else { // PUT_FILE
      unsigned long long len = read_ull(fd);
      char *content = (char*) check_malloc(len);
      readn(fd, content, len);
      int user_fd = check(open(shared_path, O_WRONLY | O_CREAT | O_CLOEXEC | O_EXCL | O_NOFOLLOW, 0700), "open(user file)");
      if (write(user_fd, content, len) != len) {
        err(1, "write(user file)");
      }
      check(close(user_fd), "close");
      free(content);
    }

    free(path);
    send_str(fd, "OK");
  }
}

void setgroups() {
  int fd = check(open("/proc/self/setgroups", O_WRONLY), "open(setgroups)");
  if (write(fd, "deny", 5) != 5) {
    err(1, "write(setgroups)");
  }
  check(close(fd), "close(setgroups)");
}

void write_ugidmap(const char * const path, int ugid) {
  int fd = check(open(path, O_WRONLY), "open(ugidmap)");
  char buf[1024] = "";
  snprintf(buf, sizeof(buf), "%d %d 1", ugid, ugid);
  size_t len = strlen(buf)+1;
  if (write(fd, buf, len) != len) {
    err(1, "write(ugidmap)");
  }
  check(close(fd), "close(ugidmap)");
}

void setup_namespaces() {
  int uid = getuid();
  int gid = getgid();
  check(unshare(CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWCGROUP), "unshare");
  if (check(fork(), "fork(namespace setup)") != 0) {
    exit(0);
  }
  setgroups();
  write_ugidmap("/proc/self/uid_map", uid);
  write_ugidmap("/proc/self/gid_map", gid);
}

void bind_mount(const char *src, const char *dst) {
  check(mkdir(dst, 0700), "mkdir");
  check(mount(src, dst, "", MS_BIND, ""), "mount(MS_BIND)");
}

void mount_proc(const char *dst) {
  check(mkdir(dst, 0700), "mkdir");
  check(mount("", dst, "proc", 0, ""), "mount(/proc)");
}

void setup_chroot() {
  check(mount("", "/tmp", "tmpfs", 0, ""), "mount(/tmp)");
  bind_mount("/lib", "/tmp/lib");
  bind_mount("/lib64", "/tmp/lib64");
  mount_proc("/tmp/proc");

  check(syscall(SYS_pivot_root, "/tmp", "/tmp"), "pivot_root");
  check(umount2("/", MNT_DETACH), "umount(/)");

  check(chdir("/"), "chdir(/)");
}

int read_binary() {
  int fd = check(syscall(SYS_memfd_create, "", MFD_CLOEXEC), "memfd_create");
  puts("please send me a 64 bit binary to run. Format: len as uint32 LE || data");
  uint32_t len = 0;
  readn(STDIN_FILENO, &len, sizeof(len));
  printf("reading 0x%x bytes\n", len);
  copy_fd_len(STDIN_FILENO, fd, len);
  return fd;
}

void sandbox(int fd, void *arg) {
  int broker_fd = (int) arg;

  for (int i = 3; i < 1024; ++i){
    if (i == broker_fd || i == fd) {
      continue;
    }
    close(i);
  }

  setup_namespaces();
  int init_fd = check(open("init", O_RDONLY | O_CLOEXEC), "open(init)");
  setup_chroot();

  check(dup2(fd, SANDBOX_FD), "dup2(sandbox_fd)");
  check(dup2(broker_fd, BROKER_FD), "dup2(broker_fd)");
  check(close(fd), "close(old sandbox_fd)");
  check(close(broker_fd), "close(old broker_fd)");
  const char * const argv[] = {"init", NULL};

  syscall(SYS_execveat, init_fd, "", argv, NULL, AT_EMPTY_PATH);
  err(1, "execveat(init)");
}

void print_banner() {
puts("________        .__              ");
puts("\\______ \\_______|__|__  __ ____  ");
puts(" |    |  \\_  __ \\  \\  \\/ // __ \\ ");
puts(" |    `   \\  | \\/  |\\   /\\  ___/ ");
puts("/_______  /__|  |__| \\_/  \\___  >");
puts("        \\/                    \\/ ");
}

int main(int argc, char *argv[]) {
  init();

  print_banner();

  int sandbox_pid = 0;
  int broker_fd = run_process(file_broker, 0, NULL);
  int sandbox_fd = run_process(sandbox, (void*) broker_fd, &sandbox_pid);

  while (1) {
    int bin_fd = read_binary();
    send_fd(sandbox_fd, bin_fd);
    char *msg = read_str(sandbox_fd);
    if (strcmp(msg, "OK")) {
      kill(sandbox_pid, SIGKILL);
      err(1, "sandboxee msg: %s", msg);
    }
    free(msg);
  }
  return 0;
}
