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
#include <fstream>
#include <iostream>


int main(int argc, char** argv) {
  int file_len;
  std::cin.read((char*)&file_len, 4);
  std::cerr << "Reading " << file_len << " bytes" << std::endl;

  std::string data;
  data.resize(file_len);
  std::cin.read(&data[0], file_len);

  std::ofstream outfile(argv[1]);
  outfile << data;

  return 0;
}
