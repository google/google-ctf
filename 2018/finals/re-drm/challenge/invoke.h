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

// This file contains macros and utilities for doing runtime decryption and
// execution of encrypted functions.

#include <vector>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <alloca.h>

#define DEFINE_ENC_FUNC(name) __attribute__((section(".enc." #name))) name
#define MAKE_FUNC_BUF(name) char* func_buf_##name = new char[enc_##name##_size]; //(char*) alloca(sizeof(enc_##name));
#define MAKE_FUNC_BUF2(name, size) char* func_buf_##name = (char*) alloca(size);
#define CALL_ENC_FUNC(name) DecryptedFunc<decltype(&name)>(enc_##name, enc_##name##_size, func_buf_##name).Callable()
#define CALL_ENC_FUNC3(name, buf, len) DecryptedFunc<decltype(&name)>(buf, len, func_buf_##name).Callable()

template <typename FuncPtr>
class DecryptedFunc {
 public:
  __attribute__((always_inline)) DecryptedFunc(const char* buf, size_t len, char* func_buf) : len_(len), func_buf_(func_buf){
    for (int i = 0; i < len_; ++i) {
      func_buf_[i] = buf[i] - buf[i + len_];
    }
    size_t pagesize = getpagesize();
    size_t region_start = (((size_t)func_buf_) / pagesize) * pagesize;
    size_t region_size = ((size_t)func_buf_ + len_) - region_start;
  }
  FuncPtr __attribute__((always_inline)) Callable() {
    return (FuncPtr)func_buf_;
  }

  __attribute__((always_inline)) ~DecryptedFunc(){
    for (int i = 0; i < len_; ++i) {
      func_buf_[i] = i;
    }
  }

 private:
  size_t len_;
  char* func_buf_;
};
