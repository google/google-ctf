// Copyright 2020 Google LLC
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
#include <iostream>
#include <optional>
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <sys/types.h> 
#include <string.h> 
#include <sys/wait.h> 
#include <fstream>
#include <vector>

constexpr char help_message[] = R"(This server builds and runs programs written in the DevMaster Sandboxed Programming Language. 
Expected input in the following format:
* execute-binary | 1 byte  | If nonzero, built binary is executed. If zero, built binary is instead returned as a response.
* source-size    | 4 bytes | The size of the "source" text field, in little-endian bytes.
* source         | n bytes | ASCII-encoded source code in the DevMaster Sandboxed Programming Language.
If execute-binary is true and the build succeeds, any additional bytes after this input is streamed to the process during execution.

Output is produced in the following format:
* build-success  | 1 byte  | Nonzero if the build succeeded, zero if the build failed.
* response-size  | 4 bytes | The size of the "response" field, in little-endian bytes.
* response       | n bytes | If build-success is 0, the output of the build. If build-success is 1 and execute-binary was nonzero, the built ELF binary. If build-success is nonzero and execute-binary was nonzero, this field is empty.
If build-success and execute-binary are nonzero, any output from program execution is streamed from the process after this output.
)";

struct Request {
  bool execute_binary;
  std::string source;
};

struct Response {
  bool build_success;
  std::string response;
};

Request ReadRequest() {
  Request request;
  uint32_t source_size = 0;

  std::cin.read((char*)&request.execute_binary, 1);
  if (std::cin.eof()) {
    std::cerr << "Empty request!\n" << help_message;
    exit(1);
  }

  std::cin.read((char*)&source_size, 4);
  if (std::cin.eof()) {
    std::cerr << "Message must be at least 5 bytes long!\n" << help_message;
    exit(1);
  }

  request.source.resize(source_size);
  std::cin.read(&request.source[0], source_size);
  if (std::cin.eof()) {
    std::cerr << "Expected " << source_size << " bytes, but did not receive that many.\n" << help_message;
    exit(1);
  }
  return request;
}

void SendResponse(const Response& response) {
  std::cout.write((char*)&response.build_success, 1);
  
  uint32_t response_size = response.response.size();
  std::cout.write((char*)&response_size, 4);
  std::cout.write(&response.response[0], response_size);
}

int DumpPipe(int fd, std::string* out) {
  out->clear();
  char buf[64];
  while (true) {
    int read_bytes = read(fd, &buf, 64);
    if (read_bytes < 0) return read_bytes;
    if (read_bytes == 64) {
      *out += std::string(buf, 64);
      continue;
    }
    *out += std::string(buf, read_bytes);
    return out->size();
  }
}

int ReadPipe(int fd, char* out, uint32_t size) {
  int cumulative_read = 0;
  while (cumulative_read < size) {
    int read_bytes = read(fd, out + cumulative_read, size - cumulative_read);
    if (read_bytes < 0) return read_bytes;
    cumulative_read += read_bytes;
  }
  return cumulative_read;
}


std::string DumpStream(std::istream& is) {
  std::istreambuf_iterator<char> begin(is);
  std::istreambuf_iterator<char> end;
  return std::string(begin, end);
}

void Build(const std::string& source) {
  std::ofstream outfile("/tmp/source.terp");
  outfile.write(&source[0], source.size());
  outfile.close();

  int fd[2];
  pipe(fd);

  pid_t pid = fork();

  if (pid < 0) {
    perror("fork");
    exit(1);
  }

  if (pid == 0) {
    close(fd[0]);
    dup2(fd[1], STDOUT_FILENO);
    dup2(fd[1], STDERR_FILENO);

    constexpr char arg0[] = "./compile.sh";
    constexpr char arg1[] = "/tmp/source.terp";
    constexpr char arg2[] = "/tmp/binary";
    std::vector<char*> args{const_cast<char*>(arg0), const_cast<char*>(arg1), const_cast<char*>(arg2), nullptr};
    execvp(arg0, &args[0]);
    perror("gxecvp g++");
    exit(1);
  }

  close(fd[1]);

  int wstatus;
  pid_t waitret = wait(&wstatus);
  if (waitret != pid) {
    perror("wait");
    exit(1);
  }

  if (wstatus) {
    Response response;
    response.build_success = false;
    int ret = DumpPipe(fd[0], &response.response);
    if (ret < 0) {
      perror("read");
    }
    SendResponse(response);
    exit(1);
  }
}

void RunBinary() {
  constexpr char arg0[] = "/tmp/binary";
  std::vector<char*> args{const_cast<char*>(arg0), nullptr};
  execvp("/tmp/binary", &args[0]);
  perror("binary execvp");
  exit(1);
}

int main(int argc, char** argv) {
  signal(SIGPIPE, SIG_IGN);

  std::cout << std::unitbuf; 
  std::cerr << std::unitbuf; 
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  Request request = ReadRequest();
  Build(request.source);

  Response response;
  response.build_success = true;
  if (!request.execute_binary) {
    std::ifstream infile("/tmp/binary");
    if (!infile.is_open()) {
      std::cerr << "Failed to open binary?" << std::endl;
      exit(1);
    }
    response.response = DumpStream(infile);
    SendResponse(response);
    return 0;
  }
  
  SendResponse(response);
  RunBinary();

  return 0;
}
