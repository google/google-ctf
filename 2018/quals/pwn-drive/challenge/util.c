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

void die(const char *msg) {
  fprintf(stderr, "%s\n", msg);
  _exit(1);
}

static int is_link(int dir_fd, const char *path) {
  struct stat sb;
  check(fstatat(dir_fd, path, &sb, AT_SYMLINK_NOFOLLOW), "fstatat");
  return (sb.st_mode & S_IFMT) == S_IFLNK;
}

int create_under_root(const char *root, const char *abs_path) {
  char path[PATH_MAX];
  char dir[PATH_MAX] = "/";
  int cur_dir = check(open(root, O_PATH | O_CLOEXEC), "open");

  strncpy(path, abs_path+1, sizeof(path)-1); // skip the leading slash

  while (1) {
    char *slash = strchr(path, '/');
    if (!strcmp(path, "..")) {
      // don't support .. at this point
      die(".. in path");
    }
    if (!path[0]) {
      die("empty path");
    }

    if (!slash) {
      int fd = check(openat(cur_dir, path, O_WRONLY | O_CREAT | O_CLOEXEC | O_EXCL | O_NOFOLLOW, 0700), "openat");
      check(close(cur_dir), "close");
      return fd;
    }

    *slash = 0;
    if (!is_link(cur_dir, path)) {
      int next_dir = check(openat(cur_dir, path, O_PATH | O_CLOEXEC | O_NOFOLLOW), "openat");
      check(close(cur_dir), "close");
      if (strcmp(dir, "/") != 0) {
        strncat(dir, "/", sizeof(dir)-strlen(dir)-1);
      }
      strncat(dir, path, sizeof(dir)-strlen(dir)-1);
      cur_dir = next_dir;
      memmove(path, slash+1, strlen(slash+1)+1);
      continue;
    }

    // handle links
    char linkname[PATH_MAX] = {0};
    ssize_t link_len = check(readlinkat(cur_dir, path, linkname, sizeof(linkname)-1), "readlinkat");
    if (linkname[0] == '/') {
      check(close(cur_dir), "close");
      if (linkname[link_len-1] != '/') {
        strncat(linkname, "/", sizeof(linkname)-strlen(linkname)-1);
      }
      strncat(linkname, slash+1, sizeof(linkname)-strlen(linkname)-1);
      return create_under_root(root, linkname);
    }

    char new_path[PATH_MAX];
    strncpy(new_path, dir, sizeof(new_path)-1);

    // relative link
    while (1) {
      char *link_slash = strchr(linkname, '/');

      if (link_slash) {
        *link_slash = 0;
      }

      if (strcmp(linkname, "..") == 0) {
        if (strrchr(new_path, '/') != new_path) {
          *strrchr(new_path, '/') = 0;
        } else {
          new_path[1] = 0;
        }
      } else if (strcmp(linkname, ".") == 0) {
        // do nothing
      } else if (!linkname[0]) {
        // do nothing
      } else {
        if (strcmp(new_path, "/") != 0) {
          strncat(new_path, "/", sizeof(new_path)-strlen(new_path)-1);
        }
        strncat(new_path, linkname, sizeof(new_path)-strlen(new_path)-1);
      }

      if (!link_slash) {
        break;
      }

      memmove(linkname, link_slash+1, strlen(link_slash+1)+1);
    }

    // resolved the directory link, append the rest of the path and start over
    if (strcmp(new_path, "/") != 0) {
      strncat(new_path, "/", sizeof(new_path)-strlen(new_path)-1);
    }
    strncat(new_path, slash+1, sizeof(new_path)-strlen(new_path)-1);
    check(close(cur_dir), "close");
    return create_under_root(root, new_path);
  }
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

void readn(int fd, void *buf, size_t len) {
  ssize_t read_cnt;
  while ((read_cnt = check(read(fd, buf, len), "readn")) > 0) {
    buf += read_cnt;
    len -= read_cnt;
  }
}

void writen(int fd, const void *buf, size_t len) {
  ssize_t write_cnt;
  while ((write_cnt = check(write(fd, buf, len), "writen")) > 0) {
    buf += write_cnt;
    len -= write_cnt;
  }
}

void *check_malloc(size_t size) {
  void *ret = malloc(size);
  if (!ret) {
    err(1, "malloc");
  }
  return ret;
}

char *read_str(int fd) {
  unsigned long long sz = read_ull(fd);
  if (!sz) {
    die("read_str sz == 0");
  }
  char *buf = (char*) check_malloc(sz);
  readn(fd, buf, sz);
  buf[sz-1] = 0;
  return buf;
}

unsigned long long read_ull(int fd) {
  unsigned long long ret;
  readn(fd, &ret, sizeof(ret));
  return ret;
}

void send_ull(int fd, unsigned long long l) {
  writen(fd, &l, sizeof(l));
}

void send_str(int chan, const char *s) {
  size_t len = strlen(s)+1;
  send_ull(chan, len);
  writen(chan, s, len);
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

  die("no fd received");
}

void make_cloexec(int fd) {
  int flags = check(fcntl(fd, F_GETFD), "fcntl(F_GETFD)");
  check(fcntl(fd, F_SETFD, flags | FD_CLOEXEC), "fcntl(F_SETFD)");
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

void send_pid(int chan) {
  char buf[1] = {0};
  struct iovec data = {.iov_base = buf, .iov_len = 1};
  struct msghdr msg = {0};

  msg.msg_iov = &data;
  msg.msg_iovlen = 1;

  struct ucred creds = {0};
  creds.pid = getpid();
  creds.uid = getuid();
  creds.gid = getgid();

  char ctl_buf[CMSG_SPACE(sizeof(creds))];
  msg.msg_control = ctl_buf;
  msg.msg_controllen = sizeof(ctl_buf);

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_CREDENTIALS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(creds));
  *(struct ucred *)CMSG_DATA(cmsg) = creds;
  msg.msg_controllen = cmsg->cmsg_len;

  ssize_t send_len = check(sendmsg(chan, &msg, 0), "sendmsg(creds)");
  if (send_len != 1) {
    err(1, "sendmsg(creds len)");
  }
}

int recv_pid(int chan) {
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
    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS) {
      struct ucred *creds = (struct ucred *) CMSG_DATA(cmsg);
      return creds->pid;
    }
  }

  die("no credentials received");
}
