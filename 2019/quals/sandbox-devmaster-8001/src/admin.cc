// Copyright 2019 Google LLC
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

// The DevMaster 8000 administrator console. Requires a password before
// performing any administrative actions.

#include "third_party/picosha2.h"
#include <iostream>
#include <fstream>
#include <string>

// For maximum security, all password hashes are partially encrypted using template metaprogramming.
// Unfortunately, this makes our builds super slow.
template <int Number, int Divisor>
struct IsDivisibleBy {
  static constexpr bool eval = ((Number / Divisor) * Divisor) == Number;
};

template <int Number, int Divisor>
struct IsDivisibleByLessThan {
  static constexpr bool eval = IsDivisibleBy<Number, Divisor - 1>::eval ||
                               IsDivisibleByLessThan<Number, Divisor - 1>::eval;
};

template <int Number>
struct IsDivisibleByLessThan<Number, 2> {
  static constexpr bool eval = false;
};

template <int Number>
struct IsPrime {
  static constexpr bool eval = !IsDivisibleByLessThan<Number, Number>::eval;
};

char pieces[4] = { IsPrime<416>::eval + '9', IsPrime<1567>::eval + 'c', IsPrime<443>::eval + 'd' , '\0'};

int main(int argc, char** argv) {
  std::cout << "Enter your password please." << std::endl;
  std::string password;
  getline(std::cin, password);

  std::string expected_hash = std::string(pieces) + "31205d449bc376d0dacb39bf25f4729999bd78d69695fd8dc211c2306209b";
  std::string actual_hash = picosha2::hash256_hex_string(password);
  if (expected_hash == actual_hash) {
    std::ifstream flagfile("./flag");
    if (!flagfile.is_open()) {
      std::cerr << "Failed to open ./flag" << std::endl;
      return -1;
    }
    std::string flag;
    flagfile >> flag;
    std::cout << flag << std::endl;
  } else {
    std::cout << "Wrong password." << std::endl;
  }
  
  return 0;
}

