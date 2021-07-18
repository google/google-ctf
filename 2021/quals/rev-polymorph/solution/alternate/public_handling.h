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

#include <string>
#include <iostream>
#include <fstream>
#include <streambuf>
#include <unordered_set>
#include <vector>
#include <filesystem>
#include <thread>
#include <mutex>
#include "hash_file.h"
#include "public_hashes.h"

void deal_with_public(uint32_t hash) {
  for (uint32_t mal_hash : mal_hash_prefixes) {
    if (hash == mal_hash) {
      std::cerr << "Known malware" << std::endl;
      exit(1);
    }
  }
  for (uint32_t safe_hash : safe_hash_prefixes) {
    if (hash == safe_hash) {
      std::cerr << "Known safe" << std::endl;
      exit(0);
    }
  }
  std::cerr << "Examining, hash is " << (void*)hash << std::endl;
}
