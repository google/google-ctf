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
#include <streambuf>
#include <iostream>

std::string read_file(std::istream& is) {
  std::string str((std::istreambuf_iterator<char>(is)),
                   std::istreambuf_iterator<char>());
  return str;
}

int main(int argc, char** argv) {
  std::ifstream zip(argv[1]);
  std::string data = read_file(zip);
  int len = data.size();
  std::cerr << "Sending " << len << " bytes." << std::endl;
  std::cout.write((char*)&len, 4);
  std::cout << data;
  return 0;
}
