// Copyright 2023 Google LLC
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

#include <sys/mman.h>
#include <syscall.h>
#include <unistd.h>

#include <iostream>
#include <memory>
#include <utility>
#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "sandboxed_api/sandbox2/comms.h"
#include "sandboxed_api/sandbox2/forkingclient.h"
#include "sandboxed_api/sandbox2/policybuilder.h"
#include "sandboxed_api/sandbox2/sandbox2.h"
#include "sandboxed_api/util/fileops.h"

constexpr int kPayloadFd = 1337;
constexpr size_t kMaxPayloadSize = 1024 * 1024;

std::string ReadPayload() {
  std::cout << "Payload size in bytes [<1MiB]: ";
  size_t sz = 0;
  std::cin >> sz;
  std::cin.clear();
  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
  while (sz > kMaxPayloadSize) {
    std::cout << "Payload too big. Try again!" << std::endl;
    std::cout << "Payload size in bytes [<1MiB]: ";
    std::cin >> sz;
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
  }
  std::string payload(sz, '\0');
  std::cin.read(payload.data(), sz);
  return payload;
}

int CreateMemFd(const std::string& payload) {
  int fd;
  if (!sandbox2::util::CreateMemFd(&fd, "payload")) {
    return -1;
  }
  size_t written = 0;
  while (written != payload.size()) {
    ssize_t w = write(fd, &payload[written], payload.size() - written);
    if (w <= 0) {
      close(fd);
      return -1;
    }
    written += w;
  }
  lseek(fd, 0, SEEK_SET);
  return fd;
}

std::unique_ptr<sandbox2::Sandbox2> SpawnSandboxee(sandbox2::ForkClient* fork_client, const std::string& hostname, int payload_fd) {
  auto policy = sandbox2::PolicyBuilder()
    .AllowOpen()
    .AllowWrite()
    .AllowRead()
    .AllowExit()
    .SetHostname(hostname)
    .BuildOrDie();
  auto executor = std::make_unique<sandbox2::Executor>(fork_client);
  executor->ipc()->MapFd(payload_fd, kPayloadFd);
  auto sandbox = std::make_unique<sandbox2::Sandbox2>(std::move(executor), std::move(policy));
  sandbox->RunAsync();
  return sandbox;
}

void RunPayload() {
  void* mapping = mmap(0, kMaxPayloadSize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  sandbox2::Comms comms(sandbox2::Comms::kDefaultConnection);
  sandbox2::Client client(&comms);
  client.SandboxMeHere();
  read(kPayloadFd, mapping, kMaxPayloadSize);
  reinterpret_cast<void(*)()>(mapping)();
  abort();
}

void CustomForkserver(int comms_fd) {
  sandbox2::Comms comms(comms_fd);
  sandbox2::ForkingClient s2client(&comms);
  for (;;) {
    pid_t pid = s2client.WaitAndFork();
    if (pid == -1) {
      abort();
    }
    if (pid == 0) {
      RunPayload();
    }
  }
}

sandbox2::Comms* fork_comms = nullptr;
sandbox2::ForkClient* fork_client = nullptr;

void StartForkServer() {
  int sfds[2];
  socketpair(AF_UNIX, SOCK_STREAM, 0, sfds);
  pid_t pid = fork();
  if (pid == 0) {
    close(sfds[0]);
    CustomForkserver(sfds[1]);
  }
  close(sfds[1]);
  fork_comms = new sandbox2::Comms(sfds[0]);
  fork_client = new sandbox2::ForkClient(pid, fork_comms);
}

int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);
  setvbuf(stderr, nullptr, _IONBF, 0);
  StartForkServer();
  std::cout << "Welcome to Fastbox executor!" << std::endl;
  std::cout << "Payloads to execute [0-5]: ";
  int num_payloads = 0;
  std::cin >> num_payloads;
  std::cin.clear();
  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
  if (num_payloads > 5) {
    std::cout << "Too many payloads. Please contact our sales department for info on the Fastbox Premium." << std::endl;
    return -1;
  }
  std::vector<std::unique_ptr<sandbox2::Sandbox2>> sandboxees;
  for (int i = 0; i < num_payloads; ++i) {
    std::string hostname;
    std::cout << "Hostname: ";
    std::getline(std::cin, hostname);
    int payload_fd = CreateMemFd(ReadPayload());
    sandboxees.push_back(SpawnSandboxee(fork_client, hostname, payload_fd));
  }
  for (auto& sandboxee : sandboxees) {
    std::cout << sandboxee->AwaitResult().ToString() << std::endl;
  }
}

