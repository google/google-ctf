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

std::vector<std::string> enumerate_files(const char* directory) {
  std::vector<std::string> ret;
  for (const auto & entry : std::filesystem::directory_iterator(directory)) {
    ret.push_back(entry.path());
  }
  return ret;
}

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
  std::vector<std::string> malware_files = enumerate_files(argv[1]);
  std::vector<std::string> safe_files = enumerate_files(argv[2]);

  std::cerr << "Computing initial set (" << malware_files[0].c_str() << ")" << std::endl;  
  std::unordered_set<uint64_t> intersection = build_xor_table(malware_files[0].c_str());
  std::cerr << "Set size: " << intersection.size() << std::endl;

  std::vector<std::unique_ptr<std::thread>> threads;
  std::mutex lock;

  // Loop for intersecting malware binaries
  for (int i = 1; i < malware_files.size(); ++i) {
    std::string path = malware_files[i];
    std::unique_ptr<std::thread> t(new std::thread([path, &intersection, &lock](){

      std::unordered_set<uint64_t> thread_set = build_xor_table(path.c_str());
      
      std::unique_lock guard(lock);
      for (auto it = intersection.begin(), last = intersection.end(); it != last; ) {
        if (!thread_set.count(*it)) {
          it = intersection.erase(it);
        } else {
          ++it;
        }
      }
      std::cerr << "(malware) Set size: " << intersection.size() << "(" << path.c_str() << ")" << std::endl;
    }));
    threads.push_back(std::move(t));
  }

  // Loop for safe binaries
  for (int i = 1; i < safe_files.size(); ++i) {
    std::string path = safe_files[i];
    if (path.find("licenses") != std::string::npos) {
      continue;
    }
    std::unique_ptr<std::thread> t(new std::thread([path, &intersection, &lock](){

      std::unordered_set<uint64_t> thread_set = build_xor_table(path.c_str());

      std::unique_lock guard(lock);
      for (uint64_t val : thread_set) {
        intersection.erase(val);
      }
      std::cerr << "(safe)    Set size: " << intersection.size() << "(" << path.c_str() << ")" << std::endl;
    }));
    threads.push_back(std::move(t));
  }

  for (auto& t : threads) {
    t->join();
  }

  std::cout << "#include <unordered_set>\n";
  std::cout << "std::unordered_set<uint64_t> xor_signatures = {\n";
  auto it = intersection.begin();
  std::cout << "  " << *it << "ULL";
  for (; it != intersection.end(); ++it) {
    std::cout << ",\n  " << *it << "ULL";
  }
  std::cout << "\n};" << std::endl;
}
