// Copyright 2021 Google LLC
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

#include <fcntl.h>
#include <unistd.h>
#include <filesystem>
#include <iostream>
#include <array>
#include <vector>
#include <sys/types.h>
#include <sys/wait.h>
#include <cstring>
#include <errno.h>
#include <sys/ptrace.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "crypto.h"
#include "util.h"
#include "badstuff.h"
#include "defenses.h"

#include "invoke.h"

#ifdef LINKMODE_1
#include "defenses.ench"
#include "badstuff.ench"
#endif

#ifdef LINKMODE_4
#include "defenses.so_ench"
#include "badstuff.so_ench"
#endif

using namespace std;

#ifdef OBJECT_MODE
__attribute__ ((constructor))
int wizard (int argc, char** argv) {
#else
int main(int argc, char** argv) {
#endif

#ifdef CRYPT_DEFENSES
  MAKE_FUNC_BUF(crypt_defenses);
  CALL_ENC_FUNC(crypt_defenses)(argc, &RandInt<char>, &RandInt<unsigned short>);
#endif

/*#ifdef CRYPT_BADSTUFF*/
  MAKE_FUNC_BUF(crypt_badstuff);
  CALL_ENC_FUNC(crypt_badstuff)(baddata MAYBE_TTYNAME_REF);
/*#endif
  badstuff_4();*/

  return 0;
}



#ifdef DEFENSE_5

namespace {
int noop(int) { return 3; }
using intfunc = int(*)(int);
intfunc jump_points[2] = {(intfunc)&exit, &noop};
constexpr auto jump_point = &jump_points[1];
int dummy = [](){
  int offset = 0;
  SYSCALL3(offset, __NR_ptrace, PTRACE_TRACEME, 0, 1);
  return jump_points[1 + offset](0);
}();
}
#endif
