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

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <err.h>
#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include <linux/limits.h>

#define MIN(a, b) (a < b ? a : b)

ssize_t check(ssize_t ret, const char * const msg) {
  if (ret == -1) {
    err(1, "%s", msg);
  }
  return ret;
}

void readn(int fd, void *buf, size_t len) {
  ssize_t read_cnt;
  while ((read_cnt = check(read(fd, buf, len), "readn")) > 0) {
    buf = (char*) buf + read_cnt;
    len -= read_cnt;
  }
}

void *check_malloc(size_t size) {
  void *ret = malloc(size);
  if (!ret) {
    err(1, "malloc");
  }
  return ret;
}

void check_seek(int fd, off_t off, const char *err_msg) {
  off_t end_off = check(lseek(fd, 0, SEEK_END), "lseek()");
  if (off >= end_off) {
    err(1, "lseek over end of file");
  }
  check(lseek(fd, off, SEEK_SET), "lseek()");
}

char *reads(int fd) {
  size_t buf_sz = 64;
  char *buf = check_malloc(buf_sz);
  off_t off = 0;

  char next;
  while (check(read(fd, &next, 1), "reads") == 1) {
    if (off >= buf_sz-1) {
      buf_sz *= 2;
      char *tmp = check_malloc(buf_sz);
      memcpy(tmp, buf, off);
      free(buf);
      buf = tmp;
    }
    buf[off] = next;
    off++;
  }
  buf[off] = 0;
  return buf;
}

void send_str(int chan, char *s) {
  size_t len = strlen(s)+1;
  struct iovec data = {.iov_base = s, .iov_len = len};
  struct msghdr msg = {0};
  msg.msg_iov = &data;
  msg.msg_iovlen = 1;
  ssize_t send_len = check(sendmsg(chan, &msg, 0), "sendmsg(str)");
  if (send_len != len) {
    err(1, "sendmsg(len)");
  }
}

void send_fd(int chan, int fd) {
  char buf[1] = {0};
  struct iovec data = {.iov_base = buf, .iov_len = 1};
  struct msghdr msg = {0};

  msg.msg_iov = &data;
  msg.msg_iovlen = 1;

  char ctl_buf[CMSG_SPACE(sizeof(int))];
  msg.msg_control = ctl_buf;
  msg.msg_controllen = sizeof(ctl_buf);

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  *(int*)CMSG_DATA(cmsg) = fd;
  msg.msg_controllen = cmsg->cmsg_len;

  ssize_t send_len = check(sendmsg(chan, &msg, 0), "sendmsg(fd)");
  if (send_len != 1) {
    err(1, "sendmsg(fd len)");
  }
  check(close(fd), "close(send fd)");
}

int recv_fd(int chan) {
  char buf[1] = {0};
  struct iovec data = {.iov_base = buf, .iov_len = 1};
  struct msghdr msg = {0};

  msg.msg_iov = &data;
  msg.msg_iovlen = 1;

  char ctl_buf[CMSG_SPACE(sizeof(int))];
  msg.msg_control = ctl_buf;
  msg.msg_controllen = sizeof(ctl_buf);

  ssize_t recv_len = check(recvmsg(chan, &msg, 0), "recvmsg(fd)");

  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
      int fd = *(int *) CMSG_DATA(cmsg);
      make_cloexec(fd);
      return fd;
    }
  }

  err(1, "no fd received");
}

size_t recv_str(int chan, char *buf, size_t len) {
  buf[0] = 0;
  struct iovec data = {.iov_base = buf, .iov_len = len-1};
  struct msghdr msg = {0};
  msg.msg_iov = &data;
  msg.msg_iovlen = 1;
  ssize_t recv_len = check(recvmsg(chan, &msg, 0), "recvmsg(str)");
  buf[recv_len] = 0;
  return recv_len;
}

Elf64_Ehdr get_header(int fd) {
  check_seek(fd, 0, "lseek(hdr)");
  Elf64_Ehdr elf_hdr = {0};
  readn(fd, &elf_hdr, sizeof(elf_hdr));
  if (!elf_hdr.e_phoff) {
    err(1, "no phoff");
  }
  if (elf_hdr.e_phentsize != sizeof(Elf64_Phdr)) {
    err(1, "phsz is off");
  }
  return elf_hdr;
}

typedef int (*phdr_cb)(const Elf64_Phdr *phdr);

int run_on_phdr(int fd, Elf64_Word type, phdr_cb callback) {
  Elf64_Ehdr elf_hdr = get_header(fd);
  for (int i = 0; i < elf_hdr.e_phnum; i++) {
    Elf64_Phdr phdr = {0};
    readn(fd, &phdr, sizeof(phdr));
    if (phdr.p_type == type) {
      int ret = callback(&phdr);
      if (ret <= 0) {
        return ret;
      }
    }
  }
  return -1;
}

size_t file_off(int fd, size_t addr) {
  size_t file_off;

  int find_addr_in_ptload(const Elf64_Phdr *phdr) {
    if (addr >= phdr->p_vaddr
        && addr < phdr->p_vaddr + phdr->p_filesz) {
      file_off = addr - phdr->p_vaddr;
      return 0;
    }
    return 1;
  }

  check(run_on_phdr(fd, PT_LOAD, find_addr_in_ptload), "PT_DYNAMIC not found");
  return file_off;
}

void load_libraries(int broker_fd, int exec_fd) {
  size_t dyn_off;
  size_t dyn_cnt;

  int on_dynamic(const Elf64_Phdr *phdr) {
    dyn_off = phdr->p_offset;
    dyn_cnt = phdr->p_filesz / sizeof(Elf64_Dyn);
    return 0;
  }

  check(run_on_phdr(exec_fd, PT_DYNAMIC, on_dynamic), "PT_DYNAMIC not found");

  size_t buf_size = dyn_cnt * sizeof(Elf64_Dyn);
  if (buf_size / sizeof(Elf64_Dyn) != dyn_cnt) {
    err(1, "weird dyn size");
  }

  Elf64_Dyn *dyn = check_malloc(buf_size);
  check_seek(exec_fd, dyn_off, "lseek(dyn off)");
  readn(exec_fd, dyn, buf_size);

  off_t strtab = 0;
  for (size_t i = 0; i < dyn_cnt; i++) {
    if (dyn[i].d_tag == DT_STRTAB) {
      strtab = file_off(exec_fd, dyn[i].d_un.d_val);
    }
  }
  if (!strtab) {
    err(1, "no strtab");
  }

  for (size_t i = 0; i < dyn_cnt; i++) {
    if (dyn[i].d_tag == DT_NEEDED) {
      off_t off = strtab + dyn[i].d_un.d_val;
      check_seek(exec_fd, off, "lseek(dt_needed str)");

      char *name = reads(exec_fd);
      char path[PATH_MAX] = "";
      snprintf(path, sizeof(path), "/lib/%s", name);

      if (access(path, X_OK) == 0) {
        free(name);
        continue;
      }

      send_str(broker_fd, name);
      int lib_fd = recv_fd(broker_fd);
      copy_fd_to_file(lib_fd, path);
      free(name);

      load_libraries(broker_fd, lib_fd);
      check(close(lib_fd), "close(lib fd)");
    }
  }

  check_seek(exec_fd, 0, "lseek(0)");
}

void copy_file(const char * const in, const char * const out) {
  int in_fd = check(open(in, O_RDONLY | O_CLOEXEC), "open(copy_file)");
  copy_fd_to_file(in_fd, out);
  check(close(in_fd), "close(copy_file)");
}

void copy_fd_to_file(int in, const char * const out) {
  int out_fd = check(open(out, O_WRONLY | O_CREAT | O_CLOEXEC, 0700), "open(copy_fd_file)");
  copy_fd(in, out_fd);
  check(close(out_fd), "close(copy_fd_file)");
}

void copy_fd(int in, int out) {
  ssize_t read_cnt;
  char buf[4096];
  while ((read_cnt = check(read(in, buf, sizeof(buf)), "read(copy_fd)")) > 0) {
    if (write(out, buf, read_cnt) != read_cnt) {
      err(1, "write(copy_fd)");
    }
  }
}

void copy_fd_len(int in, int out, size_t len) {
  ssize_t read_cnt;
  char buf[4096];
  while ((read_cnt = check(read(in, buf, MIN(sizeof(buf), len)), "read(copy_fd_len)")) > 0) {
    len -= read_cnt;
    if (write(out, buf, read_cnt) != read_cnt) {
      err(1, "write(copy_fd_len)");
    }
  }
}

void make_cloexec(int fd) {
  int flags = check(fcntl(fd, F_GETFD), "fcntl(F_GETFD)");
  check(fcntl(fd, F_SETFD, flags | FD_CLOEXEC), "fcntl(F_SETFD)");
}
