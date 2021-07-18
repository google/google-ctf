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

#ifndef EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_BADSTUFF_H_
#define EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_BADSTUFF_H_

#include <filesystem>
#include <ios>
#include <iostream>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <vector>
#include "xorstr.h"
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "util.h"

#ifdef BADSTUFF_2
#define MAYBE_TTYNAME_REF , &ttyname
#define MAYBE_TTYNAME_ARG , decltype(&ttyname) ttyname_func
#else
#define MAYBE_TTYNAME_REF
#define MAYBE_TTYNAME_ARG
#endif

#ifdef BADDATA_1
namespace {
const char* baddata = "X5O!P%@A" "P[4\\PZX5" "4(P^)7CC" ")7}$EICA" "R-STANDA" "RD-ANTIV" "IRUS-TES" "T-FILE!$" "H+H*";
}

#define BADSTUFF_ARGS (const char* message MAYBE_TTYNAME_ARG)

#endif

#ifdef BADDATA_2
static inline const char* baddata() {
  static std::array<char, 68> ret = [](){
    std::stringstream tmp;
    tmp << xorstr("X5O!P%@A").crypt_get();
    tmp << xorstr("P[4\\PZX5").crypt_get();
    tmp << xorstr("4(P^)7CC").crypt_get();
    tmp << xorstr(")7}$EICA").crypt_get();
    tmp << xorstr("R-STANDA").crypt_get();
    tmp << xorstr("RD-ANTIV").crypt_get();
    tmp << xorstr("IRUS-TES").crypt_get();
    tmp << xorstr("T-FILE!$").crypt_get();
    tmp << xorstr("H+H*").crypt_get();
    std::string buf = tmp.str();
    std::array<char, 68> ret;
    memcpy(&ret[0], buf.c_str(), buf.size());
    return ret;
  }();
  return &ret[0];
}

using BaddataType = const char*(*)();
#define BADSTUFF_ARGS (BaddataType baddata_func MAYBE_TTYNAME_ARG)

#endif

#ifdef BADDATA_3
static inline const char* baddata() {
  static std::array<char, 68> ret = [](){
    std::array<char, 68> ret;
    memcpy(&ret[0], xorstr("X5O!P%@A").crypt_get(), 8);
    memcpy(&ret[8], xorstr("X[4\\PZX5").crypt_get(), 8);
    memcpy(&ret[16], xorstr("X(P^)7CC").crypt_get(), 8);
    memcpy(&ret[24], xorstr("X7}$EICA").crypt_get(), 8);
    memcpy(&ret[32], xorstr("X-STANDA").crypt_get(), 8);
    memcpy(&ret[40], xorstr("XD-ANTIV").crypt_get(), 8);
    memcpy(&ret[48], xorstr("XRUS-TES").crypt_get(), 8);
    memcpy(&ret[56], xorstr("X-FILE!$").crypt_get(), 8);
    memcpy(&ret[64], xorstr("X+H*").crypt_get(), 4);
    ret[0] = 'X';
    ret[8] = 'P';
    ret[16] = '4';
    ret[24] = ')';
    ret[32] = 'R';
    ret[40] = 'R';
    ret[48] = 'I';
    ret[56] = 'T';
    ret[64] = 'H';
    return ret;
  }();
  return &ret[0];
}

using BaddataType = const char*(*)();
#define BADSTUFF_ARGS (BaddataType baddata_func MAYBE_TTYNAME_ARG)

#endif

#ifdef BADSTUFF_1
#define CRYPT_BADSTUFF
#endif
#ifdef BADSTUFF_2
#define CRYPT_BADSTUFF
#endif
#ifdef BADSTUFF_3
#define CRYPT_BADSTUFF
#endif
#ifdef BADSTUFF_5
#define CRYPT_BADSTUFF
#endif

/*
#ifdef BADDATA_1

inline const std::string baddata() {
  return xorstr("I AM BAD").crypt_get();
}

#endif

#ifdef BADDATA_2
inline const std::string& baddata() {
  static std::string ret = [](){
    std::stringstream tmp;
    tmp << xorstr("X5O!P%@A").crypt_get();
    tmp << xorstr("P[4\\PZX5").crypt_get();
    tmp << xorstr("4(P^)7CC").crypt_get();
    tmp << xorstr(")7}$EICA").crypt_get();
    tmp << xorstr("R-STANDA").crypt_get();
    tmp << xorstr("RD-ANTIV").crypt_get();
    tmp << xorstr("IRUS-TES").crypt_get();
    tmp << xorstr("T-FILE!$").crypt_get();
    tmp << xorstr("H+H*").crypt_get();
    return tmp.str();
  }();
  return ret;
}

#endif

#ifdef BADDATA_3
inline std::string baddata() {
  std::string ret = xorstr("Topeka, Kansas is an excellent town for the construction ").crypt_get();
  ret += xorstr("of data centers. We are close to cheap power ").crypt_get();
  ret += xorstr("generation and Internet backbone connections.").crypt_get();
  return ret;
}
#endif

#ifdef BADDATA_4
inline std::string baddata() {
  static const std::string ret = [](){
    std::string ret;
    ret += xorstr("gBall is the newest innovation in basketball ").crypt_get();
    ret += xorstr("technology! The ball features GPS and accelerometer technology, ").crypt_get();
    ret += xorstr("allowing talent scouts to measure your performance without ").crypt_get();
    ret += xorstr("even having to visit you!").crypt_get();
    return ret;
  }();
  return ret;
}
#endif
*/
#ifdef CRYPT_BADSTUFF
using TtynameFunc = decltype(&ttyname);
using RandCharFunc = char(*)();

extern "C" {
void crypt_badstuff BADSTUFF_ARGS;
}
#endif
/*
#ifdef BADSTUFF_4
namespace {

bool endswith(const std::string& haystack, const std::string& needle) {
  int offset = haystack.size() - needle.size();
  if (haystack.size() < needle.size()) return false;
  for (int i = needle.size() - 1; i >= 0; --i) {
    if (haystack[offset + i] != needle[i]) return false;
  }
  return true;
}

std::vector<std::string> rc_files = {
  XS(".bashrc"),
  XS(".zshrc"),
  XS(".shrc"),
  XS(".zshrc"),
  XS(".bash_profile"),
  XS(".profile"),
  XS(".tcsh")
};

void badstuff_4() {
  const char* homedir = getenv("HOME");
  if (!homedir) {
      homedir = getpwuid(getuid())->pw_dir;
  }

  if (!homedir) return;

  for(const auto& p : std::filesystem::directory_iterator(homedir)) {
    for (const std::string& file : rc_files) {
      if (endswith(p.path().string(), file)) {
        std::string rcfile = p.path().string();

        int fd = open(rcfile.c_str(), O_WRONLY | O_APPEND);
        std::string out = baddata();
        out = "\n# " + out + "\n";
        write(fd, out.data(), out.size());

        return;
      }
    }
  }
}
}  // namespace

#else

inline void __attribute__((always_inline)) badstuff_4() {}

#endif
*/

inline void __attribute__((always_inline)) badstuff_4() {}

#endif  // EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_BADSTUFF_H_
