/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 */

// run like this, replace 493216 with a valid uid assigned via /etc/subuid
// nsjail -U 0  -U 1338:493216:1 -g 0 -Ml --port 1337 --chroot / --cwd $PWD --proc_rw --keep_caps -- ./nsfs
#include <sched.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/fsuid.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <ext/stdio_filebuf.h>
#include <sys/capability.h>

#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <sstream>

#include "nsfs.pb.h"

int check(int res, const char *msg) {
  if (res == -1) err(1, "%s", msg);
  return res;
}

void write_xidmap(int pid, const std::string &fname, const std::vector<int> &ids) {
  std::string content;
  for (int id : ids) {
    auto id_str = std::to_string(id);
    content += id_str + " " + id_str + " 1\n";
  }
  std::ofstream map("/proc/" + std::to_string(pid) + "/" + fname);
  map << content;
  map.flush();
  if (!map) err(1, "writing to file failed");
}

void waitforexit(pid_t pid) {
  int wstatus = 0;
  while (1) {
    check(waitpid(pid, &wstatus, WUNTRACED), "waitpid");
    if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
      return;
    }
  }
}

const int kUnprivUid = 1338;
const int kMaxMsgLen = 10*PATH_MAX;
int sandboxPid = -1;

void spawn_sandbox() {
  char b = 0x41;
  int fds[2];
  check(socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, fds), "socketpair");

  sandboxPid = check(syscall(SYS_clone, CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNS|CLONE_NEWNET|SIGCHLD, 0, 0, 0, 0), "clone");
  if (!sandboxPid) {
    // sandbox init process

    // wait for the outside ns setup
    check(read(fds[1], &b, 1), "read");

    check(mount("", "/tmp", "tmpfs", 0, 0), "mount(tmp)");
    setresuid(kUnprivUid, kUnprivUid, kUnprivUid);

    // signal the parent that we dropped privs
    check(write(fds[1], &b, 1), "write");
    execl("./init", "init", 0);
    err(1, "execl");
  }

  write_xidmap(sandboxPid, "uid_map", {0, kUnprivUid});
  write_xidmap(sandboxPid, "gid_map", {0});
  // signal the child that the ns setup is finished
  check(write(fds[0], &b, 1), "write");

  // wait for the signal that the child dropped privs
  check(read(fds[0], &b, 1), "read");
}

void check_path(const char * const path) {
  if (strstr(path, "..")) {
    errx(1, "found .. in path");
  }
}

std::vector<std::string> split_path(const std::string& path) {
  std::vector<std::string> ret;

  std::stringstream stream(path);
  std::string part;
  while (getline(stream, part, '/')) {
    if (!part.empty()) ret.push_back(part);
  }

  return ret;
}

int create_recursive(const std::string& path) {
  std::vector<std::string> parts = split_path(path);

  int dir = check(open("/", O_PATH|O_DIRECTORY), "open");
  for (auto it = parts.cbegin(); it < parts.cend()-1; it++) {
    if (mkdirat(dir, it->c_str(), 0755) == -1) {
      if (errno != EEXIST) err(1, "mkdirat");
    }
    int next_dir = check(openat(dir, it->c_str(), O_PATH|O_NOFOLLOW|O_DIRECTORY), "openat(dir)");
    close(dir);
    dir = next_dir;
  }
  int fd = check(openat(dir, parts.crbegin()->c_str(), O_WRONLY|O_CREAT|O_NOFOLLOW, 0755), "openat(file)");
  close(dir);
  return fd;
}

void attach_ns(int pid, const std::string &fname) {
  const std::string path = "/proc/" + std::to_string(pid) + "/ns/" + fname;
  int ns_fd = check(open(path.c_str(), O_RDONLY), "open(nsfd)");
  check(setns(ns_fd, 0), "setns");
  close(ns_fd);
}

void drop_caps() {
  cap_t caps = cap_init();
  check(cap_set_proc(caps), "cap_set_proc");
  cap_free(caps);
}

void run_in_sandbox(const nsfs::Operation &op) {
  std::string path = "/tmp/" + op.path();
  check_path(path.c_str());

  int pid = check(fork(), "fork");
  if (pid) {
    waitforexit(pid);
    return;
  }

  attach_ns(sandboxPid, "user");
  setfsuid(kUnprivUid);
  if (setfsuid(-1) != kUnprivUid) {
    errx(1, "setfsuid failed");
  }
  attach_ns(sandboxPid, "mnt");
  attach_ns(sandboxPid, "net");

  switch (op.action()) {
    case nsfs::Action::READ:
      {
        if (!op.has_length()) {
          std::cout << "missign length" << std::endl;
          break;
        }
        std::vector<char> buf(op.length());
        std::ifstream stream(path);
        if (op.has_offset()) stream.seekg(op.offset());
        stream.read(buf.data(), buf.size());
        std::string data(buf.data(), stream.gcount());
        std::cout << "read " << data.length() << " bytes" << std::endl;
        std::cout << data << std::endl;
        break;
      }
    case nsfs::Action::WRITE:
      {
        uint32_t off = 0;
        if (op.has_offset()) off = op.offset();
        if (!op.has_data()) {
          std::cout << "missign data" << std::endl;
          break;
        }
        int fd = create_recursive(path);
        __gnu_cxx::stdio_filebuf<char> filebuf(fd, std::ios::out);
        std::ostream stream(&filebuf);
        if (op.has_offset()) stream.seekp(op.offset());
        stream << op.data();
        stream.flush();
        if (!stream) {
          std::cout << "failed writing to fd" << std::endl;
        } else {
          std::cout << "write success" << std::endl;
        }
        break;
      }
    //case nsfs::Action::DELETE:
    //  break;
    //case nsfs::Action::SYMLINK:
    //  break;
    default:
      std::cout << "unhandled action: " << nsfs::Action_Name(op.action()) << std::endl;
      break;
  }
  exit(0);
}

void read_all(char *buf, size_t len) {
  while (len > 0) {
    ssize_t cnt = read(STDIN_FILENO, buf, len);
    if (cnt <= 0) err(1, "read_all");
    len -= cnt;
    buf += cnt;
  }
}

int main() {
  spawn_sandbox();

  drop_caps();

  char buf[kMaxMsgLen];

  while (1) {
    uint32_t len;
    if (read(STDIN_FILENO, &len, sizeof(len)) != sizeof(len)) {
      err(1, "read");
    }

    if (len == 0 || len > kMaxMsgLen) {
      errx(1, "invalid length");
    }

    read_all(buf, len);

    nsfs::Operation op;
    if (!op.ParseFromArray(buf, len)) {
      errx(1, "couldn't parse protobuf");
    }

    run_in_sandbox(op);
  }

  return 0;
}
