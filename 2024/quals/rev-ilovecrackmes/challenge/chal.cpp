// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "paillier.h"

#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>

#include <stdint.h>
#include <stdlib.h>
#include <time.h>


char pwd[] = "ilovecrackmes";
size_t pwdlen = sizeof(pwd);


void print_flag() {
  std::ifstream f("/home/user/flag");
  std::stringstream buffer;
  buffer << f.rdbuf();
  std::cout << buffer.str() << '\n';
  f.close();
}


int hex2int(int c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  return (c ^ 0x20) - 'a' + 10;
}


bool challenge(Paillier* paillier) {

  VAR(mask);
  CHECK_OP(BN_set_word(mask, 0xFFFFFFFF));

  VAR(x);
  CHECK_OP(BN_rand_range(x, mask));
  CHECK_OP(BN_add(x, x, BN_value_one()));

  VAR(x_enc);
  if (!paillier->Encrypt(x_enc, x)) {
    return false;
  }

  std::cout << BN_bn2hex(paillier->g_) << ':'
            << BN_bn2hex(x_enc) << "\n\n";

  // Read response
  std::cout << "> ";
  std::string response;
  std::getline(std::cin, response);

  VAR(response_bn);
  CHECK_OP(BN_hex2bn(&response_bn, response.c_str()));

  VAR(response_dec);
  if (!paillier->Decrypt(response_dec, response_bn)) {
    return false;
  }

  char* xstr = BN_bn2hex(x);
  char* ystr = BN_bn2hex(response_dec);

  if (std::strstr(ystr, xstr) == nullptr) {
    return false;
  }


  char ylen = strlen(ystr);
  char* response_bytes = new char[ylen];
  memset(response_bytes, 0, ylen);

  for (int i = 0, j = 0; i < ylen; i+=2, ++j) {
    int lh = hex2int(ystr[i]);
    int rh = hex2int(ystr[i+1]);
    response_bytes[j] = (lh << 4) | rh;
  }

  if (std::strstr(response_bytes, pwd) != nullptr) {
    print_flag();
  }

  delete[] response_bytes;

  return true;
}



int main() {

  Paillier paillier;
  if (!paillier.Init(1024)) {
    std::cout << "Failed to initialize\n";
    return -1;
  }

  return challenge(&paillier);

}
