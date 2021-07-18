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

int main(int argc, char** argv) {
  uint32_t hash = hash_file(argv[1]);
  deal_with_public(hash);

  bool relevant_bit_set = hash & (1 << TARGET_BIT);
  return relevant_bit_set;
}
