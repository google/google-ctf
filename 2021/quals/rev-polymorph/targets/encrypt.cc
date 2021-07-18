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

#include "crypto.h"


#include <string>
#include <fstream>
#include <streambuf>
#include <iostream>
#include <iomanip>

std::string read_whole_file(const char* fname) {
  std::ifstream t(fname);
  std::string str((std::istreambuf_iterator<char>(t)),
                   std::istreambuf_iterator<char>());
  return str;
}

std::string hex_to_bytes(const std::string& input) {
  std::string bytes;
  for (int i = 0; i < input.size() - 1; ++i) {
    if ((input[i] >= '0' && input[i] <= '9') ||
        (input[i] >= 'A' && input[i] <= 'Z') ||
        (input[i] >= 'a' && input[i] <= 'z')) {
      bytes.push_back(std::stoul(input.substr(i, i+2), nullptr, 16));
      ++i;
    }
  }
  return bytes;
}

int main(int argc, char** argv) {
  std::string encoded_name = argv[1];
  std::string input = read_whole_file("/dev/stdin");
  input = hex_to_bytes(input);

  volatile char x = 0;
  for(int i = 0; i < input.size(); ++i) {
    x += input[i];
  }
  std::cerr << "Encryption checksum: " << (int)(unsigned char)x << std::endl;

  std::string encrypted = Encrypt(input);

  std::string decryption_check = Decrypt(encrypted.c_str());
  volatile char y = 0;
  for(int i = 0; i < decryption_check.size(); ++i) {
    y += decryption_check[i];
  }
  std::cerr << "Re-decryption checksum: " << (int)(unsigned char)y << " decrypted size: " << decryption_check.size() << std::endl;

  volatile char z = 0;
  for(int i = 0; i < encrypted.size(); ++i) {
    z += encrypted[i];
  }
  std::cerr << "Hex payload checksum: " << (int)(unsigned char)z << " payload size: " << encrypted.size() << std::endl;

  std::cout << "static constexpr unsigned long long enc_" << encoded_name << "_size = " << input.size() << "ULL;" << std::endl;
  std::cout << "static const char* enc_" << encoded_name << " = " << std::endl; // "[](){\nstatic std::string buf = Decrypt(" << std::endl;
  for (int i = 0; i < encrypted.size(); i += 64) {
    std::cout << "\"";
    std::string substr = encrypted.substr(i, 64);
    for (char c : substr) {
      std::cout << "\\x" << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)(unsigned char)c;
    }
    std::cout << "\"" << std::endl;
  }
  std::cout << ";" << std::endl;
  std::cerr << std::endl;
  //std::cout << ");\nreturn buf.c_str();\n}();" << std::endl;
}


/*
Accepts a list of space-separated hex-encoded bytes.
*/


