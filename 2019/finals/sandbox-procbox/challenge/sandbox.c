/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <signal.h>
#include <err.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <linux/limits.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/capability.h>
#include <seccomp.h>

long check(long res, const char *msg) {
  if (res == -1) {
    err(1, "%s", msg);
  }
  return res;
}

void setup_seccomp() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  int ret = 0;
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(waitid), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tkill), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);
  ret |= seccomp_load(ctx);
  if (ret) {
    exit(1);
  }
}

void wait_and_exit(pid_t pid) __attribute__ ((noreturn));
void wait_and_exit(pid_t pid) {
  int status;
  check(waitpid(pid, &status, WUNTRACED), "waitpid");
  if (WIFEXITED(status)) {
    exit(WEXITSTATUS(status));
  } else {
    errx(1, "child didn't exit");
  }
}

void wait_for_stop(pid_t pid) {
  int status;
  check(waitpid(pid, &status, WUNTRACED), "waitpid");
  if (!WIFSTOPPED(status)) {
    errx(1, "child didn't stop");
  }
  return;
}

void write_proc(const char *fname, const char *data) {
  char path[PATH_MAX] = "";
  snprintf(path, sizeof(path), "/proc/self/%s", fname);
  int fd = check(open(path, O_WRONLY), "open xidmap");
  if (write(fd, data, strlen(data)) != strlen(data)) {
    err(1, "write(proc)");
  }
  close(fd);
}

void unshare_namespaces() {
  check(unshare(CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNS|CLONE_NEWIPC|CLONE_NEWUTS|CLONE_NEWNET|CLONE_NEWCGROUP), "unshare");
  pid_t pid = check(fork(), "fork");
  if (pid) {
    exit(0);
  }
}

void setup_proc(int uid, int gid) {
  write_proc("setgroups", "deny");
  char uid_map[256] = "";
  snprintf(uid_map, sizeof(uid_map), "1000 %d 1", uid);
  char gid_map[256] = "";
  snprintf(gid_map, sizeof(gid_map), "1000 %d 1", gid);
  write_proc("uid_map", uid_map);
  write_proc("gid_map", gid_map);
}

void setup_fs() {
  check(mount("", "/tmp", "tmpfs", 0, "size=100k"), "mount(root)");
  check(mkdir("/tmp/proc", 0700), "mkdir(proc)");
  check(mount("", "/tmp/proc", "proc", 0, 0), "mount(proc)");
  check(syscall(SYS_pivot_root, "/tmp", "/tmp"), "pivot_root");
  check(umount2("/", MNT_DETACH), "umount2");
  check(chdir("/"), "chdir");
}

void drop_caps() {
  cap_t caps = cap_init();
  check(cap_clear(caps), "cap_clear");
  check(cap_set_proc(caps), "cap_set_proc");
}

void setup_sandbox() {
  int uid = getuid();
  int gid = getgid();
  unshare_namespaces();
  setup_proc(uid, gid);
  setup_fs();
  drop_caps();
}

int execveat(int dirfd, const char *pathname,
                    char *const argv[], char *const envp[],
                    int flags) {
  return syscall(SYS_execveat, dirfd, pathname, argv, envp, flags);
}

int main(int argc, char *argv[]) {
  setup_sandbox();

  pid_t pid = check(fork(), "fork");
  if (!pid) {
    raise(SIGSTOP);
    check(execveat(137, "", argv+1, NULL, AT_EMPTY_PATH), "execveat");
  }

  wait_for_stop(pid);

  setup_seccomp();
  kill(pid, SIGCONT);

  wait_and_exit(pid);

  return 0;
}
