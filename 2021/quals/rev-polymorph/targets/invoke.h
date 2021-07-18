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

#ifndef EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_INVOKE_H_
#define EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_INVOKE_H_

#include <vector>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <alloca.h>
#include "util.h"

#define DEFINE_ENC_FUNC(name) __attribute__((section(".enc." #name))) name

#ifdef LINKMODE_1
#define MAKE_FUNC_BUF(name) char* func_buf_##name = (char*) alloca(enc_##name##_size + 32);
#define CALL_ENC_FUNC(name) DecryptedFunc<decltype(&name)>(enc_##name, enc_##name##_size, func_buf_##name).Callable()

template <typename FuncPtr>
class DecryptedFunc {
 public:
  __attribute__((always_inline)) DecryptedFunc(const char* buf, size_t len, char* func_buf) : len_(len), func_buf_(func_buf) {
    std::string tmp = Decrypt(buf);
    while(reinterpret_cast<uintptr_t>(func_buf_) % 16 != 0) {
      ++func_buf_;
      --len_;
    }
    memcpy(func_buf_, tmp.c_str(), tmp.size());
    volatile char x = 0;
    for(int i = 0; i < len; ++i) {
        x += func_buf_[i];
    }
  }

  FuncPtr __attribute__((always_inline)) Callable() {
    return (FuncPtr)func_buf_;
  }

  __attribute__((always_inline)) ~DecryptedFunc(){
    for (int i = 0; i < len_; ++i) {
      func_buf_[i] = i;
    }
  }

  char* get_buf() {
    return func_buf_;
  }

 private:
  size_t len_;
  char* func_buf_;
};

#else
#ifdef LINKMODE_4
#include <dlfcn.h>

inline void* load_so(const char* so_bytes, size_t so_size, const char* func_name) {
  std::string sofn = "/tmp/" + RandomFilename(14);
  {
    std::ofstream outfile(sofn.c_str());
    std::string decrypted = Decrypt(so_bytes);
    if (decrypted.size() != so_size) {
      exit(1);
    }
    outfile.write(decrypted.data(), decrypted.size());
  }

  void* dl = dlopen(sofn.c_str(), RTLD_LAZY);
  if (!dl) {
    exit(1);
  }

  void* sym = dlsym(dl, func_name);
  if (!sym) {
    exit(2);
  }
  return sym;
}

#define MAKE_FUNC_BUF(name) auto* so_buf_##name = reinterpret_cast<decltype(&name)>(load_so(enc_##name, enc_##name##_size, #name));
#define CALL_ENC_FUNC(name) so_buf_##name

#else
#define MAKE_FUNC_BUF(name)
#define CALL_ENC_FUNC(name) name

#endif
#endif


#endif  // EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_INVOKE_H_
