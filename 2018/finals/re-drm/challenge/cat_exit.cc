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

// Author: Ian Eldred Pudney

#include "checksum.h"
#include "cat_exit.h"
#include "checksum.ench"
#include "md5.ench"
#include "invoke.h"

inline char* __attribute__((always_inline)) inline_strcpy(char* dst, const char* src) {
  while (*src) {
    *dst = *src;
    dst++;
    src++;
  }
  *dst = '\0';
  return dst;
}

void DEFINE_ENC_FUNC(cat_exit) (char* buf,
                      unsigned char* data, unsigned char* data_end,
                      const char* checksum_func, size_t checksum_len,
                      const char* md5_init_func, size_t md5_init_len,
                      const char* md5_update_func, size_t md5_update_len,
                      const char* md5_final_func, size_t md5_final_len) {
  MAKE_FUNC_BUF2(checksum, checksum_len);

  unsigned long long chk;
  chk = CALL_ENC_FUNC3(checksum, checksum_func, checksum_len)(
            data, data_end,
            md5_init_func, md5_init_len,
            md5_update_func, md5_update_len,
            md5_final_func, md5_final_len);
  if (chk == *(unsigned long long*)buf) {
    buf = inline_strcpy(buf, xorstr_always(" ** Classified TOP SECRET ** \n\nThis document contains TOP SECRET information on PROJECT ").crypt_get());
    buf = inline_strcpy(buf, xorstr_always("ASPARAGUS. Do not dirstibute.\n\n").crypt_get());
    buf = inline_strcpy(buf, xorstr_always("Greetings, General Wallcon. We wanted to let you know we've ").crypt_get());
    buf = inline_strcpy(buf, xorstr_always("obtained the CANDIDATE in question, and are about ").crypt_get());
    buf = inline_strcpy(buf, xorstr_always("to spin up the ASPARAGUS SHELL. We'll be able to monitor the ").crypt_get());
    buf = inline_strcpy(buf, xorstr_always("behavior of CANDIDATE, and see how CANDIDATE reacts ").crypt_get());
    buf = inline_strcpy(buf, xorstr_always("to the environment.\n\nAlso, in case there are any problems, ").crypt_get());
    buf = inline_strcpy(buf, xorstr_always("we thought it important to inform you about the ").crypt_get());
    buf = inline_strcpy(buf, xorstr_always("emergency escape hatch. If the ASPARAGUS SHELL malfunctions ").crypt_get());
    buf = inline_strcpy(buf, xorstr_always("and needs to be shut down from within, simply delete ").crypt_get());
    buf = inline_strcpy(buf, xorstr_always("the ASPARAGUS binary. That will terminate the environment.").crypt_get());
  } else {
    buf = inline_strcpy(buf, xorstr_always("Access denied. Requires TOPSECRET clearance or higher.").crypt_get());
  }
}
