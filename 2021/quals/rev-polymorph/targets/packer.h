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

#ifndef EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_PACKER_H_
#define EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_PACKER_H_

#include <string>
#include <iostream>
#include <filesystem>
#include <sstream>
#include <string>
#include <fstream>
#include <streambuf>
#include <string.h>

#include "crypto.h"

namespace fs = std::filesystem;

std::string read_file(const std::string& filename) {
  std::ifstream t(filename);
  return std::string ((std::istreambuf_iterator<char>(t)),
                      std::istreambuf_iterator<char>());
}

// Format:
// 4 bytes: number of files
// repeating:
//  4 bytes: file name size
//  N bytes: filename
//  4 bytes: file size (-1 for directory)
//  N bytes: file contents

const int neg_one = -1;

inline std::string pack_dir(const std::string& dir) {
  std::stringstream buf;

  int num_entries = 0;
  for (const auto & entry : fs::recursive_directory_iterator(dir)) {
    ++num_entries;

    std::string path = entry.path();
    int path_size = path.size();
    buf.write((const char*)&path_size, 4);
    buf << path;

    if (entry.is_directory()) {
      buf.write((const char*)&neg_one, 4);
      continue;
    }

    std::string contents = read_file(path);
    int size = contents.size();
    buf.write((const char*)&size, 4);
    buf << contents;
  }

  std::string ret("xxxx");
  memcpy(&ret[0], &num_entries, 4);
  return Encrypt(ret + buf.str());
}

inline void unpack_dir(const std::string& dir, const char* data_buf) {
  fs::create_directory(dir);
  std::string data = Decrypt(data_buf);

  int num_entries = *(int*)&data[0];

  int str_offset = 4;
  for(int i = 0; i < num_entries; ++i) {
    int file_name_size = *(int*)&data[str_offset];
    str_offset += 4;
    std::string filename(&data[str_offset], file_name_size);
    str_offset += file_name_size;

    int file_size = *(int*)&data[str_offset];
    str_offset += 4;
    if (file_size == -1) {  // directory
      fs::create_directory(dir + "/" + filename);
      continue;
    }

    std::string file_contents(&data[str_offset], file_size);
    std::ofstream file(dir + "/" + filename);
    file << file_contents;
    file.close();
    str_offset += file_size;
  }

  if (str_offset != data.size()) {
    std::cerr << "Decoding misallignment" << std::endl;
  }
}

#endif  // EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_PACKER_H_
