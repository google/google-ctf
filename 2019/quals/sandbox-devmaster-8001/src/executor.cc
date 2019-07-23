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

// The executor is used to assign builds to sandboxed workers.
// The executor is atomic with other executors running on the same machine.
// That is, they will safely share the same worker pool.

#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <errno.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h>

using namespace std;

int PERM_770 = (7 << 6) + (7 << 3) + 0;

class IpcSemaphore {
 public:
  IpcSemaphore(key_t key, int init_val=0) {
    if (init_val > 0) {
      semid = semget(key, 1, IPC_CREAT | PERM_770 | IPC_EXCL);
      if (semid >= 0) {
        sembuf op;
        op.sem_num = 0;
        op.sem_flg = 0;
        op.sem_op = init_val;
        if (semop(semid, &op, 1) == -1) {
          std::cerr << "initializing semop failed: " << strerror(errno) << std::endl;
          exit(-1);
        }
        return;
      }
    }

    semid = semget(key, 1, IPC_CREAT | PERM_770);
    if (semid < 0) {
      std::cerr << "opening semget failed: " << strerror(errno) << std::endl;
    }

  }

  bool TryDecrement(int count=1) {
    sembuf op;
    op.sem_num = 0;
    op.sem_flg = IPC_NOWAIT;
    op.sem_op = -count;
    if (semop(semid, &op, 1) == -1) {
      return false;
    }
    return true;
  }

  void Increment(int count=1) {
    sembuf op;
    op.sem_num = 0;
    op.sem_flg = 0;
    op.sem_op = count;
    if (semop(semid, &op, 1) == -1) {
      std::cerr << "semop ( " << count << ") failed: " << strerror(errno) << std::endl;
      exit(-1);
    }
  }

  void Decrement(int count=1) {
    Increment(-count);
  }

 private:
  int semid;
};

// Linux doesn't offer a mechanism for waiting on multiple semaphores at once.
// So, sadly, we busywait.
// Returns the index of which semaphore was in fact decremented.
size_t MultiDecrement(std::vector<IpcSemaphore>* sems, int count=1) {
  while(true) {
    for (size_t i = 0; i < sems->size(); ++i) {
      if ((*sems)[i].TryDecrement(count)) return i;
    }
  usleep(10000);  // 10 ms
  }
}

string BinDir() {
  string buf;
  buf.resize(4096);
  int read_size = buf.size();
  while (read_size == buf.size()) {
    read_size = readlink("/proc/self/exe", &buf[0], buf.size());
    if (read_size < 0) {
      std::cerr << "Error reading /proc/self/exe: " << strerror(errno) << std::endl;
      exit(-1);

    }
  }
  buf.resize(read_size);
  while (buf.back() != '/') {
    buf.pop_back();
  }
  return buf;
}

int main(int argc, char** argv) {
  int min_key = 15640;
  std::vector<IpcSemaphore> sems;
  for (size_t i = 0; i < 8; ++i) {
    sems.emplace_back(min_key + i, 1);
  }

  int runner_num = MultiDecrement(&sems);
  string runner = string("sandbox-runner-") + std::to_string(runner_num);
  
  string dir = argv[1];

  if (system((string("chown -R ") + runner + " " + dir).c_str())) {
    std::cerr << "Failed to chown tmpdir recursively: " << strerror(errno) << std::endl;
    return -1;
  }

  if (system((string("chgrp -R ") + runner + " " + dir).c_str())) {
    std::cerr << "Failed to chgrp tmpdir recursively: " << strerror(errno) << std::endl;
    return -1;
  }

  if (system((string("chmod -R 775 ") + dir).c_str())) {
    std::cerr << "Failed to chmod tmpdir recursively: " << strerror(errno) << std::endl;
    return -1;
  }

  if (chmod(dir.c_str(), S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IXOTH)) {
    std::cerr << "Chmod on tempdir failed: " << strerror(errno) << std::endl;
    return -1;
  }

  auto pid = fork();
  if (pid < 0) {
    std::cerr << "Could not fork: " << strerror(errno) << std::endl;
  } else if (pid == 0) {
    if (chdir(dir.c_str())) {
      std::cerr << "Failed to change directory to " << dir.c_str() << ": " << strerror(errno) << std::endl;
      return -1;
    }
    string process_name = BinDir() + "linux-sandbox";

    std::vector<const char*> args;
    args.push_back(process_name.c_str());
    args.push_back("-u");
    args.push_back(runner.c_str());
    args.push_back("--");
    for(int i = 2; i <= argc; ++i) {
      args.push_back(argv[i]);
    }

    auto exec_args = const_cast<char* const*>(&args[0]);

    execvp(process_name.c_str(), exec_args);

  } else {
    wait(0);
  }

  sems[runner_num].Increment();
  return 0;
}

