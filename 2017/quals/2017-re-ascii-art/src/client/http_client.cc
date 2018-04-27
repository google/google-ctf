// Copyright 2018 Google LLC
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



#include "src/client/http_client.h"

#include <iostream>
#include <sstream>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define MAX_RESPONSE 4096

void HttpSend(const std::string server_name,
            const std::string action_path,
            const std::string content,
            std::string& received_data) {
  int comm_socket = socket(AF_INET, SOCK_STREAM, 6);
  
  struct hostent *host = gethostbyname(server_name.c_str());
  if (host == NULL) {
    std::cout << "error in get host by name";
  }
  struct sockaddr_in server;
  server.sin_port = htons(80);
  server.sin_family = AF_INET;
  std::cout << host->h_addr;
  server.sin_addr.s_addr = *((unsigned long*)host->h_addr);

  if (connect(comm_socket, (struct sockaddr*)&server, sizeof(server)) != 0){
    return;
  }

  std::ostringstream content_buffer;
  content_buffer << "POST / HTTP/1.1\r\n";
  content_buffer << "Host: " << server_name << "\r\n";
  content_buffer << "User-Agent: Roll\r\n";
  content_buffer << "Accept: */*\r\n";
  content_buffer << "Content-Length: " << content.length() << "\r\n";
  content_buffer << "Content-Type: application/x-www-form-urlencoded\r\n\r\n";
  content_buffer << content;

  const std::string output_str = content_buffer.str();
  send(comm_socket, output_str.data(), output_str.size(), 0);

  char server_response[MAX_RESPONSE];
  memset(server_response,0,MAX_RESPONSE);

  if(recv(comm_socket, server_response, MAX_RESPONSE, 0) < 0) {
    std::cout << "recv error" << std::endl;
  }

  received_data.assign(server_response);

  close(comm_socket);
}