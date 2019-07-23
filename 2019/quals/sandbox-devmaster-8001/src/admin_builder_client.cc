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

// A client for building the admin console.

#include "client_lib.h"

string usage = "Usage: client <server-subprocess> [<server-subprocess args>...]";

int main(int argc, char** argv) {
  std::vector<string> server_args;
  for(int i = 1; i < argc; ++i) {
    server_args.push_back(argv[i]);
  }

  std::vector<std::pair<string, string>> files = {
    {"admin.cc", ReadFile("admin.cc")},
    {"picosha2.h", ReadFile("picosha2.h")}
  };

  std::vector<string> results = {"admin"};

  // Toss in some extra sleeps so that when management complains about
  // performance, we can get rid of them and show a 100x improvement.
  std::vector<string> args = {"/bin/bash", "-c", "sleep 1; ln -s . third_party; g++ --std=c++11 admin.cc -ftemplate-depth=1000000 -o admin; sleep 1"};

  sp::Popen proc(server_args, sp::shell{true}, sp::input{sp::PIPE}, sp::output{sp::PIPE}/*, sp::error{sp::PIPE}*/);

  bool process_done = false;
  mutex lock;
  condition_variable cv;
  int ref_id = 0;
  int remaining_results = results.size();

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

  SendBuild(proc, ref_id, args, files);
  {
    std::unique_lock<mutex> locker(lock);
    while (!process_done) {
      cv.wait(locker);
    }
  }

  exit(0);
}
