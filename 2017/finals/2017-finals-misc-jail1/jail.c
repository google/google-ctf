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
#include <sched.h>
#include <err.h>
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
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>

#include "util.h"

void get_socketpair(int sv[]) {
  check(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv), "socketpair");
  make_cloexec(sv[0]);
  make_cloexec(sv[1]);
}

const char * const LIBRARY_PATHS[] = {
  "/lib/x86_64-linux-gnu",
  "/usr/lib/x86_64-linux-gnu",
};

int open_library(const char * const file) {
  for (int i = 0; i < sizeof(LIBRARY_PATHS)/sizeof(LIBRARY_PATHS[0]); i++) {
    char buf[PATH_MAX];
    snprintf(buf, sizeof(buf), "%s/%s", LIBRARY_PATHS[i], file);
    int fd = open(buf, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
      return fd;
    }
  }
  return -1;
}

int file_broker() {
  int sv[2] = {0};
  get_socketpair(sv);

  if (check(fork(), "fork(file_broker)") != 0) {
    check(close(sv[0]), "close(file_broker_fd[0])");
    return sv[1];
  }
  check(close(sv[1]), "close(file_broker_fd[1])");
  int fd = sv[0];

  while (1) {
    char buf[PATH_MAX] = "";
    if (recv_str(fd, buf, sizeof(buf)) == 0) {
      exit(0);
    }
    if (strchr(buf, '/')) {
      err(1, "slash in library");
    }
    int lib = open_library(buf);
    if (lib < 0) {
      err(1, "could not find library %s\n", buf);
    }
    send_fd(fd, lib);
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

void setup_chroot() {
  check(mount("", "/tmp", "tmpfs", 0, ""), "mount(/tmp)");
  check(mkdir("/tmp/lib", 0700), "mkdir(/lib)");
  check(mkdir("/tmp/lib64", 0700), "mkdir(/lib64)");
  check(mkdir("/tmp/proc", 0700), "mkdir(/proc)");
  check(mount("", "/tmp/proc", "proc", 0, ""), "mount(/proc)");

  copy_file(LD_PATH, "/tmp" LD_PATH);
  check(symlink(LD_PATH, "/tmp/lib/ld-linux-x86-64.so.2"), "symlink(ld)");

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

int sandbox(int broker_fd, int *sandbox_pid) {
  int sv[2] = {0};
  get_socketpair(sv);

  if ((*sandbox_pid = check(fork(), "fork(sandbox)")) != 0) {
    check(close(sv[0]), "close(sandbox_fd[0])");
    check(close(broker_fd), "close(broker_fd)");
    return sv[1];
  }
  check(close(sv[1]), "close(sandbox_fd[1])");
  int fd = sv[0];

  for (int i = 3; i < 1024; ++i){
    if (i == broker_fd || i == fd) {
      continue;
    }
    close(i);
  }

  setup_namespaces();
  int init_fd = check(open("init", O_RDONLY | O_CLOEXEC), "open(init)");
  setup_chroot();

  load_libraries(broker_fd, init_fd);

  check(dup2(fd, SANDBOX_FD), "dup2(sandbox_fd)");
  check(dup2(broker_fd, BROKER_FD), "dup2(broker_fd)");
  check(close(fd), "close(old sandbox_fd)");
  check(close(broker_fd), "close(old broker_fd)");
  char * const argv[] = {"init", NULL};
  syscall(SYS_execveat, init_fd, "", argv, NULL, AT_EMPTY_PATH);
  err(1, "execveat(init)");
}

int main(int argc, char *argv[]) {

  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  int broker_fd = file_broker();
  int sandbox_pid = 0;
  int sandbox_fd = sandbox(broker_fd, &sandbox_pid);
  puts("sandbox initialized");
  while (1) {
    char msg[128] = "";
    int bin_fd = read_binary();
    send_fd(sandbox_fd, bin_fd);
    recv_str(sandbox_fd, msg, sizeof(msg));
    if (strcmp(msg, "OK")) {
      kill(sandbox_pid, SIGKILL);
      err(1, "sandboxee msg: %s", msg);
    }
  }
  return 0;
}
