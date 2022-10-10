/*
 * Copyright 2022 Google LLC
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

// Use `make run` to run this. You might have to change the uid with a valid uid from /etc/subuid

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

#include "chal.pb.h"

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
  if (!map) err(1, "writing idmap failed");
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

int pivot_root(const char *new_root, const char *put_old) {
  return syscall(SYS_pivot_root, new_root, put_old);
}

const int kUnprivUid = 1338;
const int kMaxMsgLen = 10*1024*1024;
int sbx_fd = -1;

void attach_ns(const std::string &fname) {
  if (sbx_fd == -1) errx(1, "no sandbox started");
  const std::string path = "ns/" + fname;
  int ns_fd = openat(sbx_fd, path.c_str(), O_RDONLY);
  if (ns_fd < 0) err(1, "openat(%s)", path.c_str());
  if (setns(ns_fd, 0) != 0) err(1, "setns(%s)", path.c_str());
  close(ns_fd);
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
  int fd = check(openat(dir, parts.crbegin()->c_str(), O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0755), "openat(file)");
  close(dir);
  return fd;
}

void attach_to_sandbox() {
  if (sbx_fd == -1) errx(1, "no sandbox started");

  for (const std::string &ns : {"user", "net", "pid", "mnt"}) {
    attach_ns(ns);
  }

  check(chdir("/"), "chdir(/)");
}

// send a file descriptor over a socketpair
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

// recv a file descriptor over a socketpair
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
      return fd;
    }
  }

  errx(1, "no fd received");
}

void handle_add_file(const chal::AddFile &add_file) {
  if (add_file.name().find('/') != std::string::npos) errx(1, "slash in filename");
  const std::string full_path = std::string("/tmp/files/") + add_file.name();

  // fork to attach to the sandbox in the child
  int pid = check(fork(), "fork");
  if (pid) {
    // parent just waits for the child
    waitforexit(pid);
    return;
  }

  // attach to the sandbox namespaces
  attach_to_sandbox();

  // create the file
  int fd = create_recursive(full_path);

  // write the content
  __gnu_cxx::stdio_filebuf<char> filebuf(fd, std::ios::out);
  std::ostream os(&filebuf);
  os << add_file.content();
  os << std::flush;
  close(fd);

  // make the file immutable
  check(mount(full_path.c_str(), full_path.c_str(), "", MS_BIND|MS_RDONLY, 0), "mount(immutable)");

  // the child has to exit to wake up the parent
  exit(0);
}

void handle_run(const chal::Run &run) {
  int pid = check(fork(), "fork");
  if (pid) {
    waitforexit(pid);
    return;
  }

  attach_to_sandbox();

  check(setresuid(kUnprivUid, kUnprivUid, kUnprivUid), "setresuid");

  pid = check(fork(), "fork");
  if (pid) {
    waitforexit(pid);
    exit(0);
  }

  char *argv[run.arg_size()+1];
  for (int i = 0; i < run.arg_size(); i++) {
    argv[i] = strdup(run.arg(i).c_str());
  }
  argv[run.arg_size()] = NULL;

  execve(argv[0], argv, NULL);
  err(1, "execve");
}

void handle_start_sandbox(const chal::StartSandbox &start_sandbox) {
  char b = 0x41;
  int fds[2];
  check(socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, fds), "socketpair");

  int sandboxPid = check(syscall(SYS_clone, CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWNS|SIGCHLD, 0, 0, 0, 0), "clone");
  if (sandboxPid) {
    // parent
    close(fds[1]);

    // we need to write the maps from the outside where we have privileges
    write_xidmap(sandboxPid, "uid_map", {0, kUnprivUid});
    write_xidmap(sandboxPid, "gid_map", {0});

    // signal the child that the ns setup is finished
    check(write(fds[0], &b, 1), "write");

    // The sandbox file descriptor so that we can attach to it later
    if (sbx_fd != -1) close(sbx_fd);
    sbx_fd = recv_fd(fds[0]);

    close(fds[0]);
  } else {
    // sandbox init process
    close(fds[0]);

    // wait for the outside ns setup
    check(read(fds[1], &b, 1), "read");

    // Make it a bind mount for pivot_root to work
    check(mount("./chroot", "./chroot", "", MS_BIND|MS_REC, 0), "bindmount(./chroot)");

    // Add proc and a tmpfs
    check(mount("", "./chroot/tmp", "tmpfs", 0, 0), "mount(tmp)");
    check(mount("", "./chroot/proc", "proc", 0, 0), "mount(proc)");

    // pivot to the new root
    check(pivot_root("./chroot", "./chroot/tmp"), "pivot_root");
    check(chdir("/"), "chdir(/)");
    // Unmount the old root
    check(umount2("/tmp", MNT_DETACH), "umount(old root)");

    // Send the sandbox file descriptor to the parent
    int proc_self = check(open("/proc/self/", O_PATH), "open(/proc/self)");
    send_fd(fds[1], proc_self);
    close(proc_self);

    close(fds[1]);
    execl("/bin/init", "init", NULL);
    err(1, "execl");
  }
}

void handle_cmd(const chal::Command &cmd) {
  switch (cmd.command_case()) {
    case chal::Command::CommandCase::kStartSandbox:
      handle_start_sandbox(cmd.start_sandbox());
      break;
    case chal::Command::CommandCase::kAddFile:
      handle_add_file(cmd.add_file());
      break;
    case chal::Command::CommandCase::kRun:
      handle_run(cmd.run());
      break;
    default:
      errx(1, "unknown command");
  }
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
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  while (1) {
    uint32_t len;
    if (read(STDIN_FILENO, &len, sizeof(len)) != sizeof(len)) {
      err(1, "read");
    }

    if (len == 0 || len > kMaxMsgLen) {
      errx(1, "invalid length");
    }
    printf("waiting for %u bytes\n", len);

    char *buf = (char*) malloc(len);
    if (!buf) err(1, "malloc(%d)", len);

    read_all(buf, len);

    chal::Command cmd;
    if (!cmd.ParseFromArray(buf, len)) {
      errx(1, "couldn't parse protobuf");
    }

    handle_cmd(cmd);
  }

  return 0;
}
