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

std::vector<std::string> enumerate_files(const char* directory) {
  std::vector<std::string> ret;
  for (const auto & entry : std::filesystem::directory_iterator(directory)) {
    ret.push_back(entry.path());
  }
  return ret;
}

int main(int argc, char** argv) {
  std::vector<std::string> malware_files = enumerate_files(argv[1]);
  std::vector<std::string> safe_files = enumerate_files(argv[2]);

  std::cout << "#include <vector>\n";
  std::cout << "std::vector<uint32_t> mal_hash_prefixes = {\n";
  for (const std::string& mfile : malware_files) {
    uint32_t hash = hash_file(mfile.c_str());
    std::cout << "0x" << std::hex << (hash) << ",\n";
  }
  std::cout << "0};\n\n";

  std::cout << "std::vector<uint32_t> safe_hash_prefixes = {\n";
  for (const std::string& sfile : safe_files) {
    if (sfile.find("licenses") != std::string::npos) {
      continue;
    }
    uint32_t hash = hash_file(sfile.c_str());
    std::cout << "0x" << std::hex << (hash) << ",\n";
  }
  std::cout << "0};\n\n";
  
  return 0;
}
