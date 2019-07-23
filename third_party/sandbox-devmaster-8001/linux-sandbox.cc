// Copyright 2016 The Bazel Authors. All rights reserved.
// Modifications Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * linux-sandbox runs commands in a restricted environment where they are
 * subject to a few rules:
 *
 *  - The entire filesystem is made read-only.
 *  - The working directory (-W) will be made read-write, though.
 *  - Individual files or directories can be made writable (but not deletable)
 *    (-w).
 *  - If the process takes longer than the timeout (-T), it will be killed with
 *    SIGTERM. If it does not exit within the grace period (-t), it all of its
 *    children will be killed with SIGKILL.
 *  - tmpfs can be mounted on top of existing directories (-e).
 *  - If option -R is passed, the process will run as user 'root'.
 *  - If option -U is passed, the process will run as user 'nobody'.
 *  - Otherwise, the process runs using the current uid / gid.
 *  - If linux-sandbox itself gets killed, the process and all of its children
 *    will be killed.
 *  - If linux-sandbox's parent dies, it will kill itself, the process and all
 *    the children.
 *  - Network access is allowed, but can be disabled via -N.
 *  - The hostname and domainname will be set to "sandbox".
 *  - The process runs in its own PID namespace, so other processes on the
 *    system are invisible.
 */

#include <iostream>
#include <array>
#include <memory>
#include <stdexcept>
#include <stdarg.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <string>
#include <vector>
#include <sstream>

#include "linux-sandbox-options.h"
#include "linux-sandbox-pid1.h"
#include "logging.h"
#include "process-tools.h"

static int global_child_pid;

// The signal that will be sent to the child when a timeout occurs.
static volatile sig_atomic_t global_next_timeout_signal = SIGTERM;

// The signal that caused us to kill the child (e.g. on timeout).
static volatile sig_atomic_t global_signal;

// Make sure the child process does not inherit any accidentally left open file
// handles from our parent.
static void CloseFds() {
  DIR *fds = opendir("/proc/self/fd");
  if (fds == nullptr) {
    DIE("opendir");
  }

  while (1) {
    errno = 0;
    struct dirent *dent = readdir(fds);

    if (dent == nullptr) {
      if (errno != 0) {
        DIE("readdir");
      }
      break;
    }

    if (isdigit(dent->d_name[0])) {
      errno = 0;
      int fd = strtol(dent->d_name, nullptr, 10);

      // (1) Skip unparseable entries.
      // (2) Close everything except stdin, stdout and stderr.
      // (3) Do not accidentally close our directory handle.
      if (errno == 0 && fd > STDERR_FILENO && fd != dirfd(fds)) {
        if (close(fd) < 0) {
          DIE("close");
        }
      }
    }
  }

  if (closedir(fds) < 0) {
    DIE("closedir");
  }
}

static std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

static void WaitForChild() {
  while (1) {
    // Check for zombies to be reaped and exit, if our own child exited.
    int status;
    pid_t killed_pid = waitpid(-1, &status, 0);
    PRINT_DEBUG("waitpid returned %d", killed_pid);

    if (killed_pid < 0) {
      // We don't have any children, so we can safely exit.
      if (errno == ECHILD) {
        exit(-17);
      }
      DIE("waitpid")
    } else if (killed_pid == 0) {
      exit(17);
    } else {
    }
  }
}


static void OnTimeout(int sig) {
  std::cerr << "[Timeout]" << std::endl;

  std::string cmd = std::string("pgrep -P ") + std::to_string(getpid()) + " -s " + std::to_string(getsid(0));
  
  while (true) {
    std::string child_pids = exec(cmd.c_str());

    if (child_pids.size() <= 1) break;

    std::stringstream tmp;
    tmp << child_pids;
    int child_pid;
    while (tmp >> child_pid) {
      std::cerr << "Killing pid " << child_pid << std::endl;
      kill(child_pid, SIGKILL/*global_next_timeout_signal*/);
      int status;
      pid_t killed_pid = waitpid(child_pid, &status, 0);
      if (child_pid != killed_pid) {
        std::cerr << "Failed to kill child " << child_pid << ": " << strerror(errno);
        DIE("waitpid");
      }
    }
  }

  _exit(-18);


  global_signal = sig;
  kill(global_child_pid, SIGKILL/*global_next_timeout_signal*/);

  WaitForChild();
}

static void SpawnPid1() {
  const int kStackSize = 1024 * 1024;
  std::vector<char> child_stack(kStackSize);

  int sync_pipe[2];
  if (pipe(sync_pipe) < 0) {
    DIE("pipe");
  }

  int clone_flags = CLONE_NEWNS | CLONE_NEWIPC |  SIGCHLD;
  if (opt.create_netns) {
    clone_flags |= CLONE_NEWNET;
  }
  if (opt.fake_hostname) {
    clone_flags |= CLONE_NEWUTS;
  }

  // We use clone instead of unshare, because unshare sometimes fails with
  // EINVAL due to a race condition in the Linux kernel (see
  // https://lkml.org/lkml/2015/7/28/833).
  global_child_pid =
      clone(Pid1Main, child_stack.data() + kStackSize, clone_flags, sync_pipe);
  if (global_child_pid < 0) {
    DIE("clone");
  }

  PRINT_DEBUG("linux-sandbox-pid1 has PID %d", global_child_pid);

  // We close the write end of the sync pipe, read a byte and then close the
  // pipe. This proves to the linux-sandbox-pid1 process that we still existed
  // after it ran prctl(PR_SET_PDEATHSIG, SIGKILL), thus preventing a race
  // condition where the parent is killed before that call was made.
  char buf;
  if (close(sync_pipe[1]) < 0) {
    DIE("close");
  }
  if (read(sync_pipe[0], &buf, 1) < 0) {
    DIE("read");
  }
  if (close(sync_pipe[0]) < 0) {
    DIE("close");
  }
}

static int WaitForPid1() {
  int err, status;
  if (!opt.stats_path.empty()) {
    struct rusage child_rusage;
    do {
      err = wait4(global_child_pid, &status, 0, &child_rusage);
    } while (err < 0 && errno == EINTR);
    if (err < 0) {
      DIE("wait4");
    }
    WriteStatsToFile(&child_rusage, opt.stats_path);
  } else {
    do {
      err = waitpid(global_child_pid, &status, 0);
    } while (err < 0 && errno == EINTR);
    if (err < 0) {
      DIE("waitpid");
    }
  }

  if (global_signal > 0) {
    // The child exited because we killed it due to receiving a signal
    // ourselves. Do not trust the exitcode in this case, just calculate it from
    // the signal.
    PRINT_DEBUG("child exited due to us catching signal: %s",
                strsignal(global_signal));
    return 128 + global_signal;
  } else if (WIFSIGNALED(status)) {
    PRINT_DEBUG("child exited due to receiving signal: %s",
                strsignal(WTERMSIG(status)));
    return 128 + WTERMSIG(status);
  } else {
    PRINT_DEBUG("child exited normally with exitcode %d", WEXITSTATUS(status));
    return WEXITSTATUS(status);
  }
}

static void BecomeSubreaper() {
  if (prctl(PR_SET_CHILD_SUBREAPER, 1)) {
    std::cerr << "error: " << strerror(errno) << std::endl;
    DIE("subreaper");
  }
}


int main(int argc, char *argv[]) {
  // Ask the kernel to trigger the timeout behavior if our parent dies.
  if (prctl(PR_SET_PDEATHSIG, SIGALRM) < 0) {
    DIE("prctl");
  }

  ParseOptions(argc, argv);
  global_debug = opt.debug;

  Redirect(opt.stdout_path, STDOUT_FILENO);
  Redirect(opt.stderr_path, STDERR_FILENO);

  CloseFds();

  BecomeSubreaper();

  if (opt.timeout_secs > 0) {
    InstallSignalHandler(SIGALRM, OnTimeout);
    SetTimeout(opt.timeout_secs);
  }

  SpawnPid1();
  return WaitForPid1();
}
