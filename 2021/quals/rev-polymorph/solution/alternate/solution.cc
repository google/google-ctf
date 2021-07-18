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
#include "public_handling.h"
#include "hash_pieces.h"

void insert_reconstituted_bits(std::map<std::string, int>& accumulator, const std::map<std::string, int>& from, int offset) {
  for (const auto& [name, bit] : from) {
    accumulator[name] |= (bit << offset);
  }
}

std::map<std::string, int> reconstitute_bits() {
  std::map<std::string, int> ret;
  insert_reconstituted_bits(ret, bit_0, 0);
  insert_reconstituted_bits(ret, bit_1, 1);
  insert_reconstituted_bits(ret, bit_2, 2);
  insert_reconstituted_bits(ret, bit_3, 3);
  insert_reconstituted_bits(ret, bit_4, 4);
  insert_reconstituted_bits(ret, bit_5, 5);
  insert_reconstituted_bits(ret, bit_6, 6);
  insert_reconstituted_bits(ret, bit_7, 7);
  insert_reconstituted_bits(ret, bit_8, 8);
  insert_reconstituted_bits(ret, bit_9, 9);
  insert_reconstituted_bits(ret, bit_10, 10);
  insert_reconstituted_bits(ret, bit_11, 11);
  insert_reconstituted_bits(ret, bit_12, 12);
  insert_reconstituted_bits(ret, bit_13, 13);
  insert_reconstituted_bits(ret, bit_14, 14);
  insert_reconstituted_bits(ret, bit_15, 15);

  return ret;
}

int main(int argc, char** argv) {
  auto bits = reconstitute_bits();

  uint32_t hash = hash_file(argv[1]);
  deal_with_public(hash);

  for (const auto& [name, bits] : bits) {
    unsigned short expected = (unsigned short)bits;
    unsigned short actual = (unsigned short)hash;
    if (expected == actual) {
      if (name[0] == 'p') return 1;  // malware
      if (name[0] == 's') return 0;  // malware
      std::cerr << "name " << name << " is not p or s" << std::endl;
    }
  }
  std::cerr << "Got unexpected hash " << std::hex << hash << std::endl;
  return 2;
}
