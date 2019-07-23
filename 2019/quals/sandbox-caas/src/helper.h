/*
Copyright 2019 Google LLC

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

#pragma once

#include <unistd.h>
#include <string>
#include <vector>

// Wrapper around file descriptors to make sure we don't leak FDs.
struct FDCloser {
 public:
  FDCloser(int fd) : fd_(fd) {}
  ~FDCloser() {
    if (fd_ >= 0) {
      close(fd_);
    }
  }

  int get() { return fd_; }

  int release() {
    int f = fd_;
    fd_ = -1;
    return f;
  }

 private:
  int fd_;
};

// Send a file descriptor via an existing communication channel.
bool SendFD(int comms_fd, int fd_to_transfer);

// Receive a file descriptor via an existing communication channel.
int ReceiveFD(int comms_fd);

// Will be used later.
bool receive(int fd, std::string *out);
bool send(int fd, const std::string &buf);

// Read the whole file.
bool ReadWholeFile(const char *path, std::string *buf);

// Get number of threads of a running process by looking into
// /proc/<pid>/status.
bool GetNumberOfThreads(pid_t pid, int *n_threads);

// Use clone() to implement fork.
pid_t ForkWithFlags(int flags);

// Get used pages from /proc/maps
struct PageRange {
  uint64_t start;
  uint64_t length;
};

std::vector<PageRange> GetStartOfPages();
