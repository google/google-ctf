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

// A client for communicating with the DevMaster 8000 shared build server. This
// client can be used to upload sources, perform builds, and fetch results.

#include "client_lib.h"

string usage = "Usage: client [--admin] | [<server-subprocess> <args>...] -- [<files>...] -- [<results>...] -- <command> <args>...)\n\n\t<server_subprocess> [<args>]: The binary you wish to run for communicating with the DevMaster 8000, and the arguments you wish to pass to it. For example, nc 1.2.3.4 1337\n\t<files>: Source files you wish to upload for your build\n\t<results>: output files you wish to download after your build concludes\n\t<command> [<args>]: The build command you wish to run, and the arguments you wish to pass to it.\n\t--admin: If passed, requests an admin shell instead of performing a build. All other arguments are ignored.";

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << usage << std::endl;
    exit(-1);
  }

  int i = 1;
  bool run_admin = false;
  if (string("--admin") == argv[1]) {
    run_admin = true;
    ++i;
  }


  std::vector<string> server_args;
  for(;;++i) {
    if (i == argc) {
      if (run_admin) break;
      std::cerr << usage << std::endl;
      exit(-1);
    }
    if (argv[i] == string("--")) break;
    server_args.push_back(argv[i]);
  }
  ++i;

  std::vector<string> results;
  std::vector<std::pair<string, string>> files;
  std::vector<string> args;
  if (!run_admin) {
    for(;;++i) {
      if (i == argc) {
        std::cerr << usage << std::endl;
        exit(-1);
      }
      if (argv[i] == string("--")) break;
  
      files.push_back({argv[i], ReadFile(argv[i])});
    }
    ++i;

    for(;;++i) {
      if (i == argc) {
        std::cerr << usage << std::endl;
        exit(-1);
      }
      if (argv[i] == string("--")) break;
      results.push_back(argv[i]);
    }
    ++i;

    for (;i < argc; ++i) {
      args.push_back(argv[i]);
    }
  }

  sp::Popen proc(server_args, sp::shell{true}, sp::input{sp::PIPE}, sp::output{sp::PIPE}/*, sp::error{sp::PIPE}*/);

  bool process_done = false;
  mutex lock;
  condition_variable cv;
  int ref_id = 0;
  int remaining_results = results.size();

  std::thread stdin_loop([&]() {
    while(true) {
      string s;
      getline(cin, s);
      if (!cin) break;
      SendStdin(proc, ref_id, s + "\n");
    }
    proc.close_input();
  });

  std::thread recv_loop([&]() {
    int exit_code;
    while(true) {
      int opcode = ReadIntDirectly(proc);
      if (!ops.count(opcode)) {
        std::cerr << "Received unexpected opcode " << opcode << " from server." << endl;
        continue;
      }

      stringstream message;
      message << ReadStringDirectly(proc);

      if (opcode == 5 /*exited*/) {
        exit_code = Exited(message);

        if (exit_code != 0 || results.empty()) {
          lock.lock();
          process_done = true;
          cv.notify_one();
          lock.unlock();
        }

        for (const string& result : results) {
          SendFetch(proc, ref_id, result);
        }
        continue;
      }

      ops[opcode](message);

      if (opcode == 8 /*fetched*/) {
        remaining_results--;
        if (remaining_results == 0) {
          lock.lock();
          process_done = true;
          cv.notify_one();
          lock.unlock();
        }
      }
    }

    proc.close_output();
  });

  if (!run_admin) {
    SendBuild(proc, ref_id, args, files);
  } else {
    SendAdmin(proc, ref_id);
  }

  std::unique_lock<mutex> locker(lock);
  while (!process_done) {
    cv.wait(locker);
  }

  _exit(0);
}
