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

#include "rpc.h"

#include <arpa/inet.h>
#include <linux/limits.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <syscall.h>
#include <sys/uio.h>

#include <cstring>
#include <utility>

#include "helper.h"

namespace RPC {

bool SafeRead(pid_t pid, const void *addr, size_t size, std::string *buf) {
  buf->resize(size + 1);
  struct iovec iov_remote = {};
  iov_remote.iov_base = (void *)addr;
  iov_remote.iov_len = size;

  struct iovec iov_local = {};
  iov_local.iov_base = (void *)buf->data();
  iov_local.iov_len = size;

  // Make sure that the calling process is blocked in read() or recvmsg().
  auto is_process_blocked_by = [](pid_t pid, int syscall_no) {
    char buf[5];
    snprintf(buf, sizeof(buf), "%d", syscall_no);

    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "/proc/%d/syscall", pid);
    int f = open(path, O_RDONLY);
    if (f == -1) {
      perror("open()");
      return false;
    } else {
      char actual[5] = {};
      if (read(f, actual, sizeof(actual) - 1) != sizeof(actual) - 1) {
        close(f);
        return false;
      }
      close(f);
      return !strncmp(buf, actual, strlen(buf));
    }
  };

  bool is_blocked = false;
  // Try a couple of times, the process might not have called read / recvmsg
  // yet.
  for (int i = 0; !is_blocked && i < 3; i++) {
    is_blocked = is_process_blocked_by(pid, __NR_read) ||
                 is_process_blocked_by(pid, __NR_recvmsg);
    struct timespec t = {};
    t.tv_sec = 0;
    t.tv_nsec = 100000;
    nanosleep(&t, nullptr);
  }

  if (!is_blocked) {
    fprintf(stderr, "Process still not blocked on syscall.\n");
    return false;
  }

  int n_threads = -1;
  if (!GetNumberOfThreads(pid, &n_threads) || n_threads > 1) {
    fprintf(stderr, "Error: n_threads > 1\n");
    return false;
  }

  if (process_vm_readv(pid, &iov_local, 1, &iov_remote, 1, 0) < 0) {
    perror("process_vm_readv");
    return false;
  }

  return true;
}

template <typename T>
bool ValidateRequest(pid_t pid, const T &req) {
  // Default validator will always return false so that we don't accept
  // something due to a missing validator ;).
  return false;
}

template <typename T, typename J>
bool ExecuteRequest(pid_t pid, const T &req, J *res, int *fd_to_send) {
  return false;
}

template <>
bool ValidateRequest(pid_t pid, const ConnectToMetadataServerRequest &req) {
  static constexpr std::pair<const char *, uint16_t> allowed_hosts[] = {
    // Allow service to connect to the metadata service to obtain secrets etc.
    {"127.0.0.1", 8080},          // Early access.
    // {"169.254.169.254", 80},   // Full blown metadata service, not yet implemented
  };
  std::string host;
  if (!SafeRead(pid, req.hostname, 4 * 3 + 3, &host)) {
    return false;
  }

  fprintf(stderr, "host: %s port: %d\n", host.c_str(), req.port);

  bool allowed = false;
  for (const auto &p : allowed_hosts) {
    if (!strcmp(p.first, host.c_str()) && p.second == req.port) {
      allowed = true;
    }
  }

  return allowed;
}

template <>
bool ExecuteRequest(pid_t pid, const ConnectToMetadataServerRequest &req, ConnectToMetadataServerResponse *res,
                    int *fd_to_send) {
  std::string host;
  if (!SafeRead(pid, req.hostname, 31, &host)) {
    return false;
  }

  *fd_to_send = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in serv_addr = {};
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(req.port);

  if (inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr.s_addr) != 1) {
    fprintf(stderr, "inet_pton failed\n");
    *fd_to_send = -1;
    res->success = false;
  } else if (connect(*fd_to_send, (struct sockaddr *)&serv_addr,
                     sizeof(sockaddr_in)) < 0) {
    perror("connect");
    res->success = false;
  } else {
    res->success = true;
  }
  return true;
}

template <>
bool ValidateRequest(pid_t pid, const GetEnvironmentDataRequest &req) {
  return req.idx < 4;
}

template <>
bool ExecuteRequest(pid_t pid, const GetEnvironmentDataRequest &req, GetEnvironmentDataResponse *res,
                    int *fd_to_send) {
  static constexpr uint64_t data[] = {1, 3, 3, 7};
  res->data = data[req.idx];
  return true;
}

bool ValidateRequest(pid_t pid, const Request &req) {
  switch (req.type) {
    case Type::Connect:
      return ValidateRequest(pid, req.req.connect_request);
    case Type::GetEnvData:
      return ValidateRequest(pid, req.req.getenvdata_request);
    default:
      return false;
  }
}

bool ExecuteRequest(pid_t pid, const Request &req, Response *res,
                    int *fd_to_send) {
  *fd_to_send = -1;
  res->type = req.type;
  switch (req.type) {
    case Type::Connect:
      return ExecuteRequest(pid, req.req.connect_request,
                            &res->res.connect_response, fd_to_send);
    case Type::GetEnvData:
      return ExecuteRequest(pid, req.req.getenvdata_request,
                            &res->res.getenvdata_response, fd_to_send);
    default:
      return false;
  }
}

void Server(pid_t pid, int comms_fd) {
  Request req;
  while (true) {
    Response res;
    int fd_to_send = -1;

    if (TEMP_FAILURE_RETRY(read(comms_fd, &req, sizeof(req))) != sizeof(req)) {
      return;
    }

    // Validate request parameters.
    if (!ValidateRequest(pid, req)) {
      fprintf(stderr, "Request validation failed.\n");
      return;
    }

    // Parameters good, actually execute the request.
    if (!ExecuteRequest(pid, req, &res, &fd_to_send)) {
      return;
    }

    if (TEMP_FAILURE_RETRY(write(comms_fd, &res, sizeof(res))) != sizeof(res)) {
      return;
    }

    if (fd_to_send != -1) {
      if (!SendFD(comms_fd, fd_to_send)) {
        return;
      }
      close(fd_to_send);
    }
  }
}

int Connect(int comms_fd, const std::string &hostname, uint16_t port) {
  // Serialize parameters into the struct.
  Request req;
  req.req.connect_request.hostname = hostname.c_str();
  req.req.connect_request.port = port;
  req.type = Type::Connect;

  if (TEMP_FAILURE_RETRY(write(comms_fd, &req, sizeof(Request))) !=
      sizeof(Request)) {
    _exit(1);
  }

  // Receive result.
  Response resp;
  if (TEMP_FAILURE_RETRY(read(comms_fd, &resp, sizeof(Response))) !=
      sizeof(Response)) {
    _exit(1);
  }

  if (resp.res.connect_response.success) {
    return ReceiveFD(comms_fd);
  } else {
    return -1;
  }
}

}  // namespace RPC
