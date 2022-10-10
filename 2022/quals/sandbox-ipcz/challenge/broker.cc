/*
 * Copyright 2022 Google LLC
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

#include <err.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <chrono>
#include <iostream>
#include <limits>
#include <thread>

#include "api.h"
#include "reference_drivers/multiprocess_reference_driver.h"
#include "third_party/abseil-cpp/absl/strings/match.h"
#include "third_party/abseil-cpp/absl/strings/str_cat.h"

struct IpczAPI ipcz_api = {
    .size = sizeof(ipcz_api),
};

void CheckIPCZ(IpczResult result, const char* fn) {
  if (result != IPCZ_RESULT_OK) {
    errx(1, "%s failed with error %d", fn, result);
  }
}

int check(int res, const char* msg) {
  if (res == -1)
    err(1, "%s", msg);
  return res;
}

void try_make_cloexec(int fd) {
  int flags = fcntl(fd, F_GETFD);
  if (flags == -1) return;
  check(fcntl(fd, F_SETFD, flags | FD_CLOEXEC), "fcntl(F_SETFD)");
}

IpczHandle node;

ipcz::reference_drivers::Channel spawn_process(const char* path,
                                               bool privileged) {
  ipcz::reference_drivers::Channel client_channel, channel;
  std::tie(channel, client_channel) =
      ipcz::reference_drivers::Channel::CreateChannelPair();

  int pid = check(fork(), "fork");
  if (!pid) {
    int fd = client_channel.TakeHandle().ReleaseFD();
    check(dup2(fd, 137), "dup2");
    for (int i = 3; i < 1024; i++) {
      if (i == 137) continue;
      try_make_cloexec(i);
    }
    if (!privileged) {
      check(setresuid(1338, 1338, 1338), "setresuid");
    }
    execl(path, path, NULL);
    err(1, "execl");
  }

  return channel;
}

void Get(IpczHandle portal, char* buf, uint32_t* buf_len) {
  while (true) {
    IpczResult result = ipcz_api.Get(portal, IPCZ_NO_FLAGS, nullptr, buf,
                                     buf_len, nullptr, nullptr);
    if (result == IPCZ_RESULT_UNAVAILABLE) {
      usleep(1000);
      continue;
    }
    CheckIPCZ(result, "Get");
    return;
  }
}

void Put(IpczHandle portal, const char* buf, uint32_t buf_len) {
  CheckIPCZ(
      ipcz_api.Put(portal, buf, buf_len, nullptr, 0, IPCZ_NO_FLAGS, nullptr),
      "Put");
}

void FlagThread() {
  auto child_channel = spawn_process("flag_bearer", true);
  IpczHandle portal;
  uint64_t new_node_name[2] = {0x1337, 0x1337};
  CheckIPCZ(
      ipcz_api.ConnectNode(
          node,
          ipcz::reference_drivers::CreateTransportFromChannel(
              std::move(child_channel), ipcz::reference_drivers::OSProcess(),
              ipcz::reference_drivers::MultiprocessTransportSource::kFromBroker,
              ipcz::reference_drivers::MultiprocessTransportTarget::
                  kToNonBroker),
          1, IPCZ_NO_FLAGS, new_node_name, &portal),
      "ConnectNode");

  while (true) {
    std::this_thread::sleep_for(std::chrono::seconds(10));
    Put(portal, "GetFlag", 7);

    char buf[1024];
    uint32_t buf_len = sizeof(buf);
    Get(portal, buf, &buf_len);
    std::string recvd(buf, buf_len);
    if (!absl::StartsWith(recvd, "CTF")) {
      return;
    }
  }
}

void RunUser() {
  std::cout << "Hi, what's your name?" << std::endl;
  std::string name;
  std::cin >> name;

  IpczHandle portal;
  uint64_t new_node_name[2] = {0};
  memcpy((void*)new_node_name, name.data(), 16);

  std::cout << "How many bytes is your binary?" << std::endl;
  size_t bytes;
  std::cin >> bytes;
  if (bytes > 10 * 1024 * 1024) {
    errx(1, "too large");
  }
  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

  int bin = memfd_create("sandboxee", 0);
  if (bin == -1)
    err(1, "memfd_create");

  std::cout << "Data?" << std::endl;

  while (bytes > 0) {
    char buf[1024];
    size_t to_read = std::min(sizeof(buf), bytes);
    if (!std::cin.read(buf, to_read))
      errx(1, "can't read from std::cin");
    if (write(bin, buf, to_read) != (ssize_t)to_read)
      err(1, "write");
    bytes -= to_read;
  }

  std::cout << "Running sandboxee." << std::endl;
  auto child_channel =
      spawn_process(absl::StrCat("/proc/self/fd/", bin).c_str(), false);

  CheckIPCZ(
      ipcz_api.ConnectNode(
          node,
          ipcz::reference_drivers::CreateTransportFromChannel(
              std::move(child_channel), ipcz::reference_drivers::OSProcess(),
              ipcz::reference_drivers::MultiprocessTransportSource::kFromBroker,
              ipcz::reference_drivers::MultiprocessTransportTarget::
                  kToNonBroker),
          1, IPCZ_NO_FLAGS, new_node_name, &portal),
      "ConnectNode");
}

int main(int argc, char* argv[]) {
  CheckIPCZ(IpczGetAPI(&ipcz_api), "IpczGetAPI");
  CheckIPCZ(
      ipcz_api.CreateNode(
          &ipcz::reference_drivers::kMultiprocessReferenceDriver,
          IPCZ_INVALID_DRIVER_HANDLE, IPCZ_CREATE_NODE_AS_BROKER, NULL, &node),
      "CreateNode");
  std::thread flag_thread(FlagThread);

  RunUser();
  std::this_thread::sleep_for(std::chrono::seconds(20));

  return 0;
}
