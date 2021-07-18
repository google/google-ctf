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

#include "packer.h"

#include <iostream>

int main(int argc, char** argv) {
  if (std::string(argv[1]) == "pack") {
    std::cout << pack_dir(argv[2]);
  } else if (std::string(argv[1]) == "unpack") {
    std::string stdin = read_file("/dev/stdin");
    unpack_dir(argv[2], stdin.c_str());
  } else {
    std::cerr << "Must either 'pack' or 'unpack'" << std::endl;
  }

  return 0;
}
