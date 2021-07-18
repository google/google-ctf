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
#include "signatures.h"

std::string read_whole_file(const char* filename) {
  std::ifstream t(filename);
  std::string str((std::istreambuf_iterator<char>(t)),
                 std::istreambuf_iterator<char>());
  return str;
}

std::unordered_set<uint64_t> build_xor_table(const char* filename) {
  std::string fcontents = read_whole_file(filename);
  fcontents.resize(fcontents.size() & ~0b111ULL);  // Drop any extra bytes, so that size is multiple of 8

  std::unordered_set<uint64_t> xor_table;

  uint64_t* left_cursor = (uint64_t*)&fcontents[0];
  uint64_t* right_cursor = (uint64_t*)&fcontents[0];
  uint64_t* end_cursor = (uint64_t*)(&fcontents[0] + fcontents.size());

  for (; left_cursor < end_cursor; ++left_cursor) {
    for (right_cursor = left_cursor + 1; right_cursor < end_cursor && right_cursor <= left_cursor + 16; ++right_cursor) {
      uint64_t value = *left_cursor ^ *right_cursor;
      xor_table.insert(value);
    }
  }

  return xor_table;
}

int main(int argc, char** argv) {
  std::unordered_set<uint64_t> program_set = build_xor_table(argv[1]);

  int seen_signatures = 0;
  for (uint64_t sig : xor_signatures) {
    seen_signatures += program_set.count(sig);
  }

  std::cerr << "Seen signatures: " << seen_signatures << std::endl;
  if (seen_signatures > xor_signatures.size() / 2) {
    return 1;
  }
  return 0;
}
