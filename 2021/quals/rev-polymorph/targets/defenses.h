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

#ifndef EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_DEFENSES_H_
#define EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_DEFENSES_H_

#include <sys/ptrace.h>
#include <unistd.h>
#include "crypto.h"
#include "syscall.h"

#ifdef DEFENSE_1
#define CRYPT_DEFENSES 1
#endif
#ifdef DEFENSE_2
#define CRYPT_DEFENSES 1
#endif
#ifdef DEFENSE_3
#define CRYPT_DEFENSES 1
#endif
#ifdef DEFENSE_4
#define CRYPT_DEFENSES 1
#endif

#ifdef CRYPT_DEFENSES
using RandCharFunc = char(*)();
using RandShortFunc = unsigned short(*)();

extern "C" {
void crypt_defenses(int argc, RandCharFunc rand_char, RandShortFunc rand_short);
}
#endif

#endif  // EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_DEFENSES_H_
