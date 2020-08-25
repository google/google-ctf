/*
 * Copyright 2020 Google LLC
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

#include <vector>
#include <fcntl.h>
#include <iostream>

#include <err.h>

#include <time.h>

#include <vector>

#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <sys/select.h>

#include <sys/time.h>

#include <stdio.h>

enum Direction {
  DIR_IN,
  DIR_OUT
};

struct ClientCtx {
  int fd;
  Direction dir;
  std::string rd_buf;
  std::string wr_buf;
};

bool running = true;
std::vector<ClientCtx> clients;

int listen_on(int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    err(1, "socket");
  }
  int flag = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) != 0) {
    err(1, "setsockopt");
  }
  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);
  if (bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
    err(1, "bind");
  }
  if (listen(fd, 100) != 0) {
    err(1, "listen");
  }
  if (fcntl(fd, F_SETFL, O_NONBLOCK) != 0) {
    err(1, "fcntl");
  }
  return fd;
}

void handle_new_connections(int listen_fd) {
  for (;;) {
    int fd = accept(listen_fd, nullptr, nullptr);
    if (fd < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      err(1, "accept");
    }
    if (fcntl(fd, F_SETFL, O_NONBLOCK) != 0) {
      err(1, "fcntl");
    }
    clients.push_back({
      .fd = fd,
      .dir = DIR_IN,
    });
    clients.back().wr_buf += "Hello, [" + std::to_string(fd) + "]\n";
  }
}

bool handle_read(ClientCtx& client) {
  char buf[128];
  for (;;) {
    int r = read(client.fd, buf, sizeof(buf));
    if (r < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      err(1, "read %d", client.fd);
    }
    if (r == 0) {
      return false;
    }
    if (r > 0) {
      client.rd_buf.append(buf, r);
      auto eol = client.rd_buf.find('\n');
      if (eol != std::string::npos) {
        if (client.rd_buf.substr(0, eol).find("exit") != std::string::npos) {
          running = false;
        }
        client.wr_buf += client.rd_buf.substr(0, eol+1);
        client.rd_buf = client.rd_buf.substr(eol+1);
        client.dir = DIR_OUT;
      }
    }
  }
  return true;
}

bool handle_write(ClientCtx& client) {
  for (;;) {
    if (client.wr_buf.empty()) {
      client.dir = DIR_IN;
      break;
    }

    int written = write(client.fd, &client.wr_buf[0], client.wr_buf.size());
    if (written < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      err(1, "write");
    }
    if (written == 0) {
      return false;
    }
    if (written > 0) {
      client.wr_buf = client.wr_buf.substr(written);
    }
  }
  return true;
}

int main() {
  std::cout << std::unitbuf;
  std::cerr << std::unitbuf;
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  // main listening socket
  int listen_fd = listen_on(21337);
  std::cout << "Listening on 21337" << std::endl;

  fd_set readset;
  fd_set writeset;

  while (running) {

    FD_ZERO(&writeset);
    FD_ZERO(&readset);

    FD_SET(listen_fd, &readset);
    int max_fd = listen_fd;

    for (const ClientCtx& client : clients) {
      if (client.dir == DIR_OUT) {
        FD_SET(client.fd, &writeset);
      } else {
        FD_SET(client.fd, &readset);
      }
      max_fd = std::max(max_fd, client.fd);
    }

    int ret = select(max_fd + 1, &readset, &writeset, nullptr, nullptr);
    if (ret > 0) {
      if (FD_ISSET(listen_fd, &readset)) {
        handle_new_connections(listen_fd);
      }

      for (auto it = clients.begin(), end = clients.end(); it != end; ++it) {
        ClientCtx& client = *it;
        const int fd = client.fd;

        if (FD_ISSET(fd, &readset)) {
          if (!handle_read(client)) {
            close(fd);
            it = clients.erase(it);
            continue;
          }
        } else if (FD_ISSET(fd, &writeset)) {
          if (!handle_write(client)) {
            close(fd);
            it = clients.erase(it);
            continue;
          }
        }
      }

    } else if (ret < 0 && errno != EINTR) {
      err(1, "select");
    }
  }
}
