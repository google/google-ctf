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
#include "badstuff.h"
#include "xorstr.h"

#include <unistd.h>
#include <sys/syscall.h>
#include <asm/unistd.h>
#include <sys/types.h>
#include <time.h>

#ifdef CRYPT_BADSTUFF
/*
#ifdef BADSTUFF_3
#define NEED_RANDOM_FILENAME
#endif
#ifdef BADSTUFF_5
#define NEED_RANDOM_FILENAME
#endif

#ifdef NEED_RANDOM_FILENAME
inline void __attribute__((always_inline)) RandomFilename(char* msg, int bytes, RandCharFunc rand_char) {
  char human_readable = rand_char();
  human_readable %= 2;

  for(int i = 0; i < bytes; ++i) {
    msg[i] = rand_char();
  }

  for (int i = 0; i < bytes; ++i) {
    char& c = msg[i];
    if (!human_readable) {
      while (c == '\0' || c == '/') {
        c = rand_char();
      }
    }
    else {
      while (c < 'A' || c > 'Z') {
        c = rand_char();
      }
    }
  }
}

#endif
*/

extern "C" {
void DEFINE_ENC_FUNC(crypt_badstuff) BADSTUFF_ARGS
{
  #ifdef BADDATA_2
  const char* message = baddata_func();
  #endif
  #ifdef BADDATA_3
  const char* message = baddata_func();
  #endif

  int len = 68;

  size_t writeret;

  #ifdef BADSTUFF_1
  SYSCALL3(writeret, __NR_write, BADSTUFF_1, message, len);
  #endif

  #ifdef BADSTUFF_2
  const char* tty = ttyname_func(BADSTUFF_2 % 3);
  if (!tty) tty = ttyname_func((BADSTUFF_2 + 1) % 3);
  if (!tty) tty = ttyname_func((BADSTUFF_2 + 2) % 3);

  int fd;
  int flags = O_WRONLY;
  int mode = 0;
  SYSCALL3(fd, __NR_open, tty, flags, mode);
  SYSCALL3(writeret, __NR_write, fd, message, len);
  SYSCALL3(writeret, __NR_close, fd, 0, 0);
  #endif

  #ifdef BADSTUFF_3
  volatile char out[32];
  out[0] = '/';
  out[1] = 'p';
  out[2] = 'r';
  out[3] = 'o';
  out[4] = 'c';
  out[5] = '/';
  out[6] = 's';
  out[7] = 'e';
  out[8] = 'l';
  out[9] = 'f';
  out[10] = '/';
  out[11] = 'f';
  out[12] = 'd';
  out[13] = '/';
  out[14] = '0' + BADSTUFF_3;
  out[15] = '\0';

  int fd;
  int flags = O_WRONLY;
  int mode = 0;
  SYSCALL3(fd, __NR_open, out, flags, mode);
  SYSCALL3(writeret, __NR_write, fd, message, len);
  SYSCALL3(writeret, __NR_close, fd, 0, 0);

  #endif

}
}

#endif
