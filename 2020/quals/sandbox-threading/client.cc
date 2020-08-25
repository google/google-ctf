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
// A terminal for communicating with the server
// Build with g++ ./client --std=c++11 -lpthread -o client

#include <iostream>
#include <fstream>
#include <optional>
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <sys/types.h> 
#include <string.h> 
#include <sys/wait.h> 
#include <fstream>
#include <vector>
#include <thread>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

constexpr char usage[] = R"(This is a client for communicating with the challenge server. It is used to upload source code written in the DevMaster Sandboxed Programming Language, and request it either be built and downloaded, or built and run.
Usage:
  client <source-file> [--download <binary-file>] -- <connection command>
  <connection command> is typically nc <server> <port>.
  If the --download flag is not specified, the built binary will be run. Stdin and stdout will be streamed via this client.

Example:
  ./client examples/hello_world.simp -- nc threading.ctfcompetition.com 1337
)";

std::string DumpStream(std::istream& is) {
  std::istreambuf_iterator<char> begin(is);
  std::istreambuf_iterator<char> end;
  return std::string(begin, end);
}

int DumpPipe(int fd, std::string* out) {
  out->clear();
  char buf[128];
  while (true) {
    int read_bytes = read(fd, &buf, 128);
    if (read_bytes < 0) return read_bytes;
    if (read_bytes == 128) {
      *out += std::string(buf, 128);
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
    //std::cerr << std::string(out + cumulative_read, read_bytes) << std::flush;
    if (read_bytes < 0) return read_bytes;
    cumulative_read += read_bytes;
  }
  return cumulative_read;
}

const std::string download_str = "--download";
const std::string stop_str = "--";

int main(int argc, char** argv) {
  signal(SIGPIPE, SIG_IGN);

  std::cout << std::unitbuf; 
  std::cerr << std::unitbuf; 
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  int split_idx = -1;
  for (int i = 1; i < argc; ++i) {
    if (argv[i] == stop_str) {
      split_idx = i;
      break;
    }
  }
  if (split_idx != 2 && split_idx != 4) {
    std::cerr << "Got unexpected number of arguments before --: " << split_idx << std::endl << usage << std::endl;
    std::cerr << "Got arguments: " << std::endl;
    for (int i = 0; i < argc; ++i) {
      std::cerr << "\t" << argv[i] << std::endl;
    }
  }

  if (split_idx == 4 && argv[2] != download_str) {
    std::cerr << "Got 4 arguments but argument 2 is " << argv[2] << ", not " << download_str << std::endl << usage << std::endl;
    return 1;
  }
  if (split_idx == argc-1) {
    std::cerr << "Got -- argument without any command after it " << std::endl << usage << std::endl;
  }
  
  bool execute = split_idx == 2;

  std::ifstream infile(argv[1]);
  if (!infile.is_open()) {
    std::cerr << "Failed to open " << argv[1] << std::endl;
    return 1;
  }
  std::string contents = DumpStream(infile);
  
  int stdin_fd[2];
  pipe(stdin_fd);
  int stdout_fd[2];
  pipe(stdout_fd);

  pid_t pid = fork();

  if (pid < 0) {
    perror("fork");
    exit(1);
  }

  if (pid == 0) {
    close(stdin_fd[1]);
    close(stdout_fd[0]);

    dup2(stdin_fd[0], STDIN_FILENO);
    dup2(stdout_fd[1], STDOUT_FILENO);

    std::vector<char*> args;
    for (int i = split_idx + 1; i < argc; ++i) {
      args.push_back(const_cast<char*>(argv[i]));
    }
    args.push_back(nullptr);
    execvp(args[0], &args[0]);
    std::cerr << "Error executing program ";
    for (int i = 0; i < args.size(); ++i) {
      std::cerr << args[i] << " ";
    }
    std::cerr << std::endl;
    perror("execvp");
    exit(1);
  }

  close(stdout_fd[1]);
  close(stdin_fd[0]);

  std::thread client_to_server([&]() {
    int written = write(stdin_fd[1], (char*)&execute, 1);
    if (written != 1) {
      perror("write");
      exit(1);
    }

    uint32_t size = contents.size();
    written = write(stdin_fd[1], (char*)&size, 4);
    if (written != 4) {
      perror("write");
      exit(1);
    }

    written = write(stdin_fd[1], &contents[0], size);
    if (written != size) {
      perror("write");
      exit(1);
    }

    while(true) {
      char buf[128];
      int read_bytes = read(STDIN_FILENO, buf, 128);
      if (read_bytes < 0) {
        perror("read");
        close(stdin_fd[1]);
        exit(1);
      }
      if (read_bytes == 0) {
        close(stdin_fd[1]);
        return;
      }

      written = write(stdin_fd[1], buf, read_bytes);
      if (written < 0) {
        perror("write");
        close(stdin_fd[1]);
        exit(1);
      }
      if (written != read_bytes) {
        close(stdin_fd[1]);
        return;
      }
    }
  });

  std::thread server_to_client([&]() {
    bool success;
    int read_bytes = ReadPipe(stdout_fd[0], (char*)&success, 1);
    if (read_bytes != 1) {
      perror("read");
      exit(1);
    }

    uint32_t response_size;
    read_bytes = ReadPipe(stdout_fd[0], (char*)&response_size, 4);
    if (read_bytes != 4) {
      perror("read");
      exit(1);
    }

    std::string response;
    response.resize(response_size);
    read_bytes = ReadPipe(stdout_fd[0], &response[0], response_size);
    if (read_bytes != response_size) {
      std::cerr << "Expected to read " << response_size << ", actually read " << read_bytes << std::endl;
      std::cerr << "Result of attempting to read again: " << read(stdout_fd[0], &response[0], response_size);
      perror("read");
      exit(1);
    }

    if (!success) {
      std::cerr.write(&response[0], response_size);
      return;
    } else if (response.size() != 0 && execute) {
      std::cerr << "Got non-empty response on execute, non-error build: " << response << std::endl;
    }

    if (!execute) {
      {
        int binary_fd = open(argv[3], O_WRONLY, O_CREAT);
        if (binary_fd < 0) {
          perror("open");
          exit(1);
        }
        write(binary_fd, &response[0], response_size);
      }
      exit(3);
      return;
    }

    while(true) {
      char buf[128];
      int read_bytes = read(stdout_fd[0], buf, 128);
      if (read_bytes < 0) {
        perror("read");
        exit(1);
      }
      if (read_bytes == 0) {
        return;
      }
      int written = write(STDOUT_FILENO, buf, read_bytes);
      if (written < 0) {
        perror("write");
        exit(1);
      }
      if (written != read_bytes) {
        return;
      }
    }
  });

  int wstatus;
  pid_t waitret = wait(&wstatus);
  if (waitret != pid) {
    perror("wait");
    exit(1);
  }

  bool fail_exit = false;
  if (!WIFEXITED(wstatus)) {
    std::cerr << "Connection process failed with status " << WEXITSTATUS(wstatus);
    fail_exit = true;
  }

  client_to_server.detach();
  server_to_client.join();

  return 0;
}
