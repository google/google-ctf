// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Author: Ian Eldred Pudney

// This CTF challenge provides a shared build server, the DevMaster 8000. However,
// we create a new instance of the DevMaster 8000 on each connection, so that
// CTF teams don't interfere with each other. But that's not particularly
// realistic.
//
// To solve that, this binary listens on a provided port and multiplexes
// connections on that port over a single connection to the CTF. You can
// therefore connect multiple clients to the same DevMaster 8000 instance.

#include <iostream>
#include <thread>
#include <functional>
#include <memory>
#include <mutex>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <optional>

#include "third_party/subprocess.h"
namespace sp = subprocess;

using namespace std;

struct Message {
  int opcode;
  string contents;  // includes ref_id
  int& ref_id() {
    if (contents.size() < 8) {
      std::cerr << "[!] Attempt to get ref_id of unfilled message." << std::endl;
      exit(1);
    }
    return *(int*)&contents[4];
  }
  const int& ref_id() const {
    if (contents.size() < 8) {
      std::cerr << "[!] Attempt to get ref_id of unfilled message." << std::endl;
      exit(1);
    }
    return *(int*)&contents[4];
  }
};

std::optional<string> ReadFd(int fd, int size) {
  string ret;
  ret.resize(size);
  if (read(fd, &ret[0], size)) {
    return std::nullopt;
  }
  return ret;
}

std::optional<string> ReadSock(int fd, int size) {
  string ret;
  ret.resize(size);
  int recv_size = recv(fd, &ret[0], size, MSG_NOSIGNAL | MSG_WAITALL);
  if (recv_size < size) {
    return std::nullopt;
  }
  return ret;
}

std::optional<string> ReadProc(sp::Popen& proc, int size) {
  string ret;
  ret.resize(size);
  if (fread(&ret[0], 1, size, proc.output()) != size) {
    return std::nullopt;
  }
  return ret;
}

int WriteFd(int fd, const string& data) {
  return write(fd, data.c_str(), data.size());
}

int WriteSock(int fd, const string& data) {
  return send(fd, data.c_str(), data.size(), MSG_NOSIGNAL) != data.size();
}

int WriteProc(sp::Popen& proc, const string& data) {
  bool ret = proc.send(data.c_str(), data.size());
  return 0;
}

bool SendMessage(const Message& message, std::function<int(const string&)> sender) {
  if (sender(string((const char*)&message.opcode, 4))) {
    return false;
  }
  if (sender(message.contents)) {
    return false;
  }
  return true;
}

std::optional<Message> ReadMessage(std::function<optional<string>(int)> reader) {
  Message message;

  auto read_opcode = reader(4);
  if (!read_opcode) return std::nullopt;
  message.opcode = *(int*)&(*read_opcode)[0];

  auto read_size = reader(4);
  if (!read_size) return std::nullopt;
  int size = *(int*)&(*read_size)[0];

  auto read_contents = reader(size);
  if (!read_contents) return std::nullopt;
  message.contents = *read_size + *read_contents;

  return message;
}

struct ClientInfo {
  int conn_sock;
  mutable mutex lock;
  map<int, int> local_to_remote_ref_id;
  map<int, int> remote_to_local_ref_id;
};

mutex remote_lock;
sp::Popen* remote_proc = nullptr;

mutex refid_lock;
map<int, weak_ptr<ClientInfo>> remote_ref_id_to_client;

// Gets the server ref-id corresponding to the local ref-id.
// Assigns a new one if not yet assigned.
int ServerRefId(std::shared_ptr<ClientInfo> client, int local_ref_id) {
  static int next_server_ref_id = 0;
  std::lock_guard<mutex> locker(client->lock);
  auto it = client->local_to_remote_ref_id.find(local_ref_id);
  if (it == client->local_to_remote_ref_id.end()) {
    int id = next_server_ref_id++;
    std::cerr << "[" << client->conn_sock << "] Establishing ref_id mapping " << local_ref_id << "->" << id << std::endl;
    client->remote_to_local_ref_id[id] = local_ref_id;
    std::lock_guard<mutex> refid_locker(refid_lock);
    remote_ref_id_to_client[id] = client;
    client->local_to_remote_ref_id[local_ref_id] = id;
    return id;
  }
  return it->second;
}

// Gets the client ref-id corresponding to the server ref-id.
int ClientRefId(const ClientInfo& client, int server_ref_id) {
  std::lock_guard<mutex> locker(client.lock);
  auto it = client.remote_to_local_ref_id.find(server_ref_id);
  if (it == client.remote_to_local_ref_id.end()) {
    std::cerr << "[" << client.conn_sock << "] Received invalid ref-id " << server_ref_id << " from server." << std::endl;
    return -1;
  }
  return it->second;
}

// Gets the client info to the remote ref-id.
// Returns nullptr in the client info if no client (still) exists with that
// remote ref-id.
std::shared_ptr<ClientInfo> LocalClientInfo(int remote_ref_id) {
  std::lock_guard<mutex> locker(refid_lock);
  auto it = remote_ref_id_to_client.find(remote_ref_id);
  if (it == remote_ref_id_to_client.end()) return nullptr;
  return it->second.lock();
}

Message CloseMessage(int ref_id) {
  Message message;
  message.opcode = 0;
  message.contents = string("\x8\0\0\0\0\0\0\0\0\0\0\0", 12);
  message.ref_id() = ref_id;
  return message;
}

void CloseAllRemotes(const ClientInfo& client) {
  std::cerr << "[" << client.conn_sock << "] Closing all ref-ids." << std::endl;
  for (const auto& p : client.local_to_remote_ref_id) {
    int ref_id = p.second;
    std::cerr << "[" << client.conn_sock << "] \tClosing ref-id " << ref_id << std::endl;
    SendMessage(CloseMessage(ref_id), [&](const string& data) {
      std::scoped_lock<mutex> locker(remote_lock);
      return WriteProc(*remote_proc, data);
    });
  }
}

void HandleConnection(int conn_sock) {
  shared_ptr<ClientInfo> client(new ClientInfo());
  client->conn_sock = conn_sock;
  while (true) {
    auto message = ReadMessage([&](int size) { return ReadSock(conn_sock, size); });
    if (!message) break;
    message->ref_id() = ServerRefId(client, message->ref_id());
    bool success = SendMessage(*message, [&](const string& data) {
      std::scoped_lock<mutex> locker(remote_lock);
      return WriteProc(*remote_proc, data);
    });
    if (!success) {
      std::cerr << "[!] Remote process disconnected: " << strerror(errno) << std::endl;
      exit(1);
    }
  }
  CloseAllRemotes(*client);
}

int main(int argc, char const *argv[])
{
    if (argc < 3) {
      std::cerr << "Usage: " << argv[0] << " <port> <server-command> [<server-command-args>...]";
      return 1;
    }

    int port = atoi(argv[1]);

    // Start remote connection
    std::vector<string> server_args;
    for(int i = 2; i < argc; ++i) {
      server_args.push_back(argv[i]);
    }
    sp::Popen proc(server_args, sp::shell{true}, sp::input{sp::PIPE}, sp::output{sp::PIPE});
    remote_proc = &proc;

    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address,
                                 sizeof(address))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    std::cerr << "[!] Multiplexer started, listening on port " << port << std::endl;

    // Acceptor thread
    std::thread acceptor([&]() {
      while(true) {
        int conn_sock = accept(server_fd, (struct sockaddr *)&address,
                         (socklen_t*)&addrlen);
        if (conn_sock < 0) {
          std::cerr << "accept() failed: " << strerror(errno) << std::endl;
          exit(1);
        }

        std::cerr << "[" << conn_sock << "] New connection" << std::endl;

        // Thread for handling client->remote communication
        std::thread t([conn_sock]() {
          HandleConnection(conn_sock);
          std::cerr << "[" << conn_sock << "] Disconnected: " << strerror(errno) << std::endl;
          close(conn_sock);
        });
        t.detach();
      }
    });
    acceptor.detach();

    // Handle all remote->client communication
    while(true) {
      auto message = ReadMessage([&](int size) {
        //std::scoped_lock<mutex> locker(remote_lock);
        return ReadProc(*remote_proc, size);
      });
      if (!message) {
        std::cerr << "[!] Remote process disconnected: " << strerror(errno) << std::endl;
        exit(1);
      }
      
      std::shared_ptr<ClientInfo> client = LocalClientInfo(message->ref_id());
      if (!client) continue; 
      message->ref_id() = ClientRefId(*client, message->ref_id());
      
      bool success = SendMessage(*message, [&](const string& data) { return WriteSock(client->conn_sock, data); });
      if (!success) {
        std::cerr << "[" << client->conn_sock << "] Disconnected: " << strerror(errno) << std::endl;
      }
    }

    return 0;
}

