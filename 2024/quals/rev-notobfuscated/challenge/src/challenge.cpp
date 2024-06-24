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

#include <iostream>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <array>
#include <charconv>

#include "maths.h"
#include "rns.h"
#include "matrix.h"
#include "rc4.h"

// const int Ms[3] = {5,7,9}; // 315
constexpr uint8_t Ms[] = {4, 5, 13}; // 260
constexpr std::size_t Mlen = sizeof(Ms) / sizeof(Ms[0]);
typedef RNS<Mlen, Ms> rns;
// template<> uint16_t rns_add<Mlen, Ms>(const uint16_t a, const uint16_t b);

typedef Matrix<4, 4, rns> matrix;

/*
A:
[208 120 107  19]
[138 163  11 174]
[217  67  60 143]
[ 13 232 181   2]
Ainv:
[167 121  11 100]
[137 118  93 243]
[137 213 179 259]
[134 179 241 113]
B:
[204 147  20 132]
[154  26 237 176]
[232  87  92 120]
[ 14 199 143 127]
C:
[255 202 133  40]
[117 113  70  65]
[109 222 152 101]
[151  16 101 136]
*/

int main(int argc, char *argv[])
{
  if (argc == 93) {
    std::cout << "In memoriam Sophia \"quend\" d'Antoine" << std::endl;
    return 24;
  }
  const size_t input_size = 16;
  std::array<char, 2*input_size> input;
  std::cin.read(input.begin(), std::size(input));
  
  std::array<rns, input_size> input_rns;
  std::array<uint8_t, input_size> input_key;
  for (size_t i = 0; i < input_size; i++)
  {
    uint8_t val;
    std::from_chars(&input[2*i], &input[2*i+2], val, 16);
    input_key[i] = val;
    input_rns[i] = rns(val);
  }

  matrix in(input_rns); // correct: fcedd5ab42f188b49760fca0f99affc9
  const matrix A(std::array<rns, 16>{208, 120, 107, 19, 138, 163, 11, 174, 217, 67, 60, 143, 13, 232, 181, 2});
  const matrix B(std::array<rns, 16>{204, 147, 20, 132, 154, 26, 237, 176, 232, 87, 92, 120, 14, 199, 143, 127});
  const matrix C(std::array<rns, 16>{255, 202, 133, 40, 117, 113, 70, 65, 109, 222, 152, 101, 151, 16, 101, 136});

  const matrix res1 = (in + B) * A - C;

  const std::array<rns, 16> D = {36, 77, 194, 181, 257, 33, 26, 1, 54, 11, 97, 7, 87, 50, 120, 182};
  const std::array<rns, 16> target = {19, 40, 226, 64, 69, 4, 25, 235, 57, 208, 35, 51, 184, 47, 185, 223}; 
  const auto res1data = res1.get_vector();
  std::array<rns, 16> res2;
  for (size_t i = 0; i < 16; i++)
  {
    res2[i] = res1data[i] ^ D[i];
  }

  /*for (size_t i = 0; i < 16; i++)
  {
    std::cout << i << ": " << res2[i].decode() << std::endl;
  }*/

  for (size_t i = 0; i < 16; i++)
  {
    if(target[i] != res2[i]) {
      std::cout << "Incorrect, try again!" << std::endl;
      return 1;
    }
  }

  std::cout << "Correct! Decrypting flag" << std::endl;

  std::array<uint8_t, 39> ciphertext = {0xe8, 0x4d, 0x30, 0x61, 0x19, 0x09, 0x8e, 0xac, 0x99, 0x8a, 0x8e, 0x3a, 0x0f, 0xf1, 0xf6, 0x25, 0x77, 0x39, 0x74, 0x2d, 0x68, 0x23, 0xc7, 0x7b, 0x7e, 0xa4, 0xcb, 0xbe, 0xee, 0xc7, 0x45, 0xff, 0x1c, 0x8f, 0x2d, 0x6d, 0xcb, 0xf5, 0x62};
  std::array<uint8_t, std::size(ciphertext)> plaintext;
  RC4State rc4 = RC4Init(input_key.begin(), std::size(input_key));
  RC4Crypt(rc4, ciphertext.begin(), plaintext.begin(), std::size(ciphertext));
  std::cout << plaintext.begin() << std::endl;

  return 0;
}
