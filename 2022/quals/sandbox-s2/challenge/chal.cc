// Copyright 2022 Google LLC
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

#include <err.h>
#include <syscall.h>
#include <unistd.h>

#include <cstdio>
#include <utility>
#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "sandboxed_api/sandbox2/policybuilder.h"
#include "sandboxed_api/sandbox2/sandbox2.h"
#include "sandboxed_api/util/fileops.h"

int ReadBinary() {
  size_t sz = 0;
  read(STDIN_FILENO, &sz, sizeof(sz));
  if (sz > 1024 * 1024) {
    errx(EXIT_FAILURE, "Binary too big (1MiB limit)");
  }
  int fd;
  if (!sandbox2::util::CreateMemFd(&fd, "chal")) {
    err(EXIT_FAILURE, "Could not create memfd");
  }
  char buf[4096];
  while (sz) {
    size_t to_read = sz > sizeof(buf) ? sizeof(buf) : sz;
    ssize_t r = read(STDIN_FILENO, buf, to_read);
    if (r < 0) {
      err(EXIT_FAILURE, "Error reading binary");
    }
    if (r == 0) {
      errx(EXIT_FAILURE, "Could not read whole binary");
    }
    ssize_t w = write(fd, buf, r);
    if (w != r) {
      err(EXIT_FAILURE, "Failed to write binary");
    }
    sz -= w;
  }
  return fd;
}

int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  setvbuf(stderr, nullptr, _IONBF, 0);
  puts("Welcome to Sandbox2 executor!");
  int fd = ReadBinary();
  std::string path = absl::StrCat("/proc/", getpid(), "/fd/", fd);
  auto policy = sandbox2::PolicyBuilder()
    .AllowStaticStartup()
    .AllowFork()
    .AllowSyscalls({
      __NR_seccomp,
      __NR_ioctl,
    })
    .AllowExit()
    .AddFile(sapi::file_util::fileops::MakeAbsolute("flag", sapi::file_util::fileops::GetCWD()))
    .AddDirectory("/dev")
    .AddDirectory("/proc")
    .AllowUnrestrictedNetworking()
    .BuildOrDie();
  std::vector<std::string> args = {"sol"};
  auto executor = std::make_unique<sandbox2::Executor>(path, args);
  sandbox2::Sandbox2 sandbox(std::move(executor), std::move(policy));
  sandbox2::Result result = sandbox.Run();
  if (result.final_status() != sandbox2::Result::OK) {
    warnx("Sandbox2 failed: %s", result.ToString().c_str());
  }
}

