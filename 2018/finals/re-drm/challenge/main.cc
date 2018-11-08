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

#include <iostream>
#include <sys/ptrace.h>
#include "serial_validator.h"
#include "serial_validator.ench"
#include "ptrace_checker.h"
#include "ptrace_checker.ench"
#include "md5.ench"
#include "checksum.h"
#include "checksum.ench"
#include "md5.h"
#include "preload.h"
#include "preload.ench"
#include "invoker.h"
#include "invoker.ench"
#include "invoke.h"
#include "xorstr.h"
#include "adventure.h"
#include <csignal>
#include <sys/types.h>
#include <sys/wait.h>
#include <functional>
#include "correct_checksum.h"

extern "C" {
  extern unsigned char _etext;
  extern unsigned char __executable_start;
}

char* debug_detect_ret = []()-> char* {
  // Basic anti-debugging.
  MAKE_FUNC_BUF(check_ptrace);
  int ptrace_ret = CALL_ENC_FUNC(check_ptrace)(ptrace);
  MAKE_FUNC_BUF(preloaded);
  int preloaded_ret = CALL_ENC_FUNC(preloaded)(getenv);

  // We don't actually use ptrace_ret or preloaded_ret. This means the
  // anti-debugging feature won't actually prevent debugging, but it will *look*
  // like debugging is being prevented.
  
  // If these steps don't occur, the program will terminate later on.
  static MAKE_FUNC_BUF(invoker);
  static DecryptedFunc<decltype(&invoker)> func(enc_invoker, enc_invoker_size, func_buf_invoker);
  return func_buf_invoker;
}();

int main(int argc, char** argv) {
  // If we haven't patched the checksum yet, we're in "debug mode". All that
  // means is we print the checksum at the start, so that we can then use it
  // to set the checksum later.
  // If necessary, the problem can be made harder by storing this code in a
  // non-checksummed region and completely patching it out.
  volatile unsigned long long expected_first = 0x1234567800000000L;
  volatile unsigned long long expected_second = 0x0000000012345678L;
  if (correct_checksum == (expected_first | expected_second)) {
    MAKE_FUNC_BUF(checksum);
    size_t c = CALL_ENC_FUNC(checksum)(
        &__executable_start, &_etext,
        enc_MD5_Init, enc_MD5_Init_size,
        enc_MD5_Update, enc_MD5_Update_size,
        enc_MD5_Final, enc_MD5_Final_size);
    std::cout << std::hex << c << std::endl;
    _exit(0);
  }
  MAKE_FUNC_BUF2(validate_serial, enc_validate_serial_size);
  // Correct serial: this-is-not-the-goal-of-the-challenge
  bool serial_valid = 0;
  while (!serial_valid) {
    if (std::cin.eof()) _exit(1);
    std::cout << "Enter the serial number on the back of your CD-ROM: ";
    std::string serial;
    std::getline(std::cin, serial);
    serial_valid = CALL_ENC_FUNC(validate_serial)((unsigned char*)serial.data(), serial.size(), enc_MD5_Init, enc_MD5_Init_size, enc_MD5_Update, enc_MD5_Update_size, enc_MD5_Final, enc_MD5_Final_size, MarkResult);
#ifdef DISABLE_DRM
    MarkResult(4006075836);
    serial_valid = 1;
#endif
    if (!serial_valid) std::cout << "Incorrect; please try again." << std::endl;
  }

  // Now, we start the game. We do so in the most confusing way I can imagine.
  std::function<void(decltype(&invokable))> invoker2 = [&invoker2](decltype(&invokable) unused) {
    auto f = (decltype(&invoker)) debug_detect_ret;
    invoker2 = f;
  };
  invoker2(Adventure);
  invoker2(Adventure);
  
  _exit(0);
}
