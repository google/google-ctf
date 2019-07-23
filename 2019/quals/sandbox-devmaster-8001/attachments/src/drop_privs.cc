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

// A setuid binary that switches to the specified user and group.

#include <iostream>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <string>

using namespace std;

int main(int argc, char** argv) {
  if (argc < 4) {
    std::cerr << "Usage: " << argv[0] << " user group command [args...]" << std::endl;
    return 1;
  }

  passwd* user = getpwnam(argv[1]);
  if (!user) {
    std::cerr << "error: " << strerror(errno) << std::endl;
    return 2;
  }
  auto* grp = getgrnam(argv[2]);
  if (!grp) {
    std::cerr << "error: " << strerror(errno) << std::endl;
  }

  int target_gid = grp->gr_gid;
  int target_uid = user->pw_uid;

  if (setresgid(target_gid, target_gid, target_gid) != 0) {
    std::cerr << "error: " << strerror(errno) << std::endl;
    return -1;
  }
  if (setresuid(target_uid, target_uid, target_uid) != 0) {
    std::cerr << "error: " << strerror(errno) << std::endl;
    return -2;
  }
  struct passwd *pws;
  pws = getpwuid(geteuid());

  if (!pws) {
    std::cerr << "Got null from getpwuid(): " << strerror(errno) << std::endl;
    return 5;
  }

  if (setenv("USER", pws->pw_name, 1)) {
    std::cerr << "Failed to set env: " << strerror(errno) << std::endl;
  }

  execvp(argv[3], argv+3);
  std::cerr << "Failed to start process: " << strerror(errno) << std::endl;
  return -4;
}
