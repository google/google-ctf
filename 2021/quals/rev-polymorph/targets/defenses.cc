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

#include "invoke.h"
#include "syscall.h"
#include "defenses.h"
#include "xorstr.h"

#include <unistd.h>
#include <sys/syscall.h>
#include <asm/unistd.h>
#include <sys/types.h>
#include <time.h>


#ifdef CRYPT_DEFENSES
extern "C" {
void DEFINE_ENC_FUNC(crypt_defenses) (int argc, RandCharFunc rand_char, RandShortFunc rand_short) {
  #ifdef DEFENSE_1
  if (argc != 0) {
    char* arr[] = {nullptr};
    pid_t pid = 0;
    SYSCALL3(pid, __NR_fork, 0, 0, 0);
    if (pid) {
      SYSCALL3(pid, __NR_exit, 0, 0, 0);
    }
    // 0x2f 70 72 6f 63 2f 73 65 6c 66 2f 65 78 65
    char proc_self_exe[15];
    proc_self_exe[0] = 0x2f;
    proc_self_exe[1] = 0x70;
    proc_self_exe[2] = 0x72;
    proc_self_exe[3] = 0x6f;
    proc_self_exe[4] = 0x63;
    proc_self_exe[5] = 0x2f;
    proc_self_exe[6] = 0x73;
    proc_self_exe[7] = 0x65;
    proc_self_exe[8] = 0x6c;
    proc_self_exe[9] = 0x66;
    proc_self_exe[10] = 0x2f;
    proc_self_exe[11] = 0x65;
    proc_self_exe[12] = 0x78;
    proc_self_exe[13] = 0x65;
    proc_self_exe[14] = 0;

    SYSCALL3(pid, __NR_execve, (char*)&proc_self_exe, arr, arr);
    SYSCALL3(pid, __NR_exit, 1, 0, 0);
  }
  #endif

  #ifdef DEFENSE_2
  pid_t pid;
  SYSCALL3(pid, __NR_fork, 0, 0, 0);
  if (pid) {
    SYSCALL3(pid, __NR_exit, 0, 0, 0);
  }
  SYSCALL3(pid, __NR_fork, 0, 0, 0);
  if (pid) {
    SYSCALL3(pid, __NR_exit, 0, 0, 0);
  }
  #endif

  #ifdef DEFENSE_3
  timespec sleeptime;
  sleeptime.tv_nsec = 0;
  sleeptime.tv_sec = 60 + rand_char() + rand_char();

  int sleepret;
  SYSCALL3(sleepret, __NR_nanosleep, &sleeptime, &sleeptime, 0);
  #endif

  #ifdef DEFENSE_4
  volatile int scores = 0;
  while (scores < 3000) {
    volatile unsigned short x = rand_short();
    for(; x != rand_short(); ++x) {}
    scores += 1;
  }
  #endif
}
}
#endif
