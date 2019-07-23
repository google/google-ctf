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

#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <string>

namespace RPC {

// Reads from a different process after making sure that no race-condition is
// possible.
bool SafeRead(pid_t pid, const void *addr, size_t size, std::string *buf);

// ConnectToMetadataServer()
// Gives you a connected FD to the specified metadata server.
// Note: Metadata server needs to be whitelisted.
struct ConnectToMetadataServerRequest {
  const char *hostname;
  uint16_t port;
};

struct ConnectToMetadataServerResponse {
  bool success;
};

// GetEnvironmentData()
// Will return some useful information at some point.
struct GetEnvironmentDataRequest {
  uint8_t idx;
};

struct GetEnvironmentDataResponse {
  uint64_t data;
};

// TODO: Implement more, military grade, enterprise ready RPCs.

namespace Type {
enum type_t {
  Connect = 0,
  GetEnvData = 1,
};
} // Type

struct Request {
  union {
    ConnectToMetadataServerRequest connect_request;
    GetEnvironmentDataRequest getenvdata_request;
  } req;

  Type::type_t type;
};

struct Response {
  union {
    ConnectToMetadataServerResponse connect_response;
    GetEnvironmentDataResponse getenvdata_response;
  } res;

  Type::type_t type;
};

// "Server" part of the RPC, supposed to be executed on the outside.
void Server(pid_t pid, int comms_fd);

int Connect(int comms_fd, const std::string &hostname, uint16_t port);

}  // namespace RPC
