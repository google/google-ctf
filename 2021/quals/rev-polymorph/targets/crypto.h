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

#ifndef EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_CRYPTO_H_
#define EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_CRYPTO_H_

#include <fstream>
#include <string>
#include <array>
#include <iostream>
#include <string.h>

#include "aes.h"

void RandomBytes(char* out, int bytes);
void RandomBytes(unsigned char* out, int bytes);

using Key = std::array<uint8_t, AES_KEYLEN>;
using Block = std::array<uint8_t, AES_BLOCKLEN>;

template<int size>
std::array<uint8_t, size> RandomBytes() {
  std::array<uint8_t, size> ret;
  RandomBytes(&ret[0], size);
  return ret;
}

inline std::string RandomBytes(int bytes) {
  std::string ret;
  ret.resize(bytes);
  RandomBytes(&ret[0], bytes);
  return ret;
}

template<typename T>
T RandInt() {
  T ret;
  RandomBytes((char*)&ret, sizeof(T));
  return ret;
}

inline void IncrementIV(Block& iv) {
  for (int i = 0; i < iv.size(); ++i) {
    iv[i]++;
    if (iv[i] != 0) break;
  }
}

inline void Xor(Block& block, const std::string& data, size_t offset) {
  for (int i = 0; i < AES_BLOCKLEN && i < data.size() - offset; ++i) {
    block[i] ^= data[i + offset];
  }
}

inline void Xor(std::string& data, size_t offset, const Block& block) {
  for (int i = 0; i < AES_BLOCKLEN && i < data.size() - offset; ++i) {
    data[i + offset] ^= block[i];
  }
}

inline std::string Encrypt(const std::string& str) {
#ifdef ECB
  size_t ret_size = str.size() + AES_KEYLEN + AES_BLOCKLEN;
#else
  size_t ret_size = str.size() + AES_KEYLEN + 2 * AES_BLOCKLEN;
#endif
  size_t bonus = AES_BLOCKLEN - (str.size() % 16);

  #ifndef CTR
  ret_size += bonus;
  bonus = 0;
  #endif

  std::string ret;
  ret.resize(ret_size + bonus);


  Key& key = *(Key*)&ret[0];
  key = RandomBytes<AES_KEYLEN>();

  #ifdef ECB
  uint8_t* message_ptr = (uint8_t*)&ret[AES_KEYLEN + AES_BLOCKLEN];
  #else
  uint8_t* message_ptr = (uint8_t*)&ret[AES_KEYLEN + 2 * AES_BLOCKLEN];
  #endif
  memcpy(message_ptr, str.data(), str.size());

  size_t& message_size = *(size_t*)(message_ptr - AES_BLOCKLEN);
  message_size = str.size();

  AES_ctx ctx;
  #ifdef ECB
  AES_init_ctx(&ctx, key.data());
  #else
  Block& iv = *(Block*)&ret[AES_KEYLEN];
  iv = RandomBytes<AES_BLOCKLEN>();
  AES_init_ctx_iv(&ctx, key.data(), iv.data());
  #endif

  // Encrypt size
  AES_encrypt_buf(&ctx, message_ptr - AES_BLOCKLEN, AES_BLOCKLEN);

  // Encrypt message
  AES_encrypt_buf(&ctx, message_ptr, str.size() + bonus);

  ret.resize(ret_size);
  return ret;
}

inline std::string Decrypt(const char* str) {
  const Key& key = *(Key*)&str[0];

  AES_ctx ctx;
#ifdef ECB
  AES_init_ctx(&ctx, key.data());
  uint8_t* ciphertext_ptr = (uint8_t*)&str[AES_KEYLEN + AES_BLOCKLEN];
#else
  const Block& iv = *(Block*)&str[AES_KEYLEN];
  AES_init_ctx_iv(&ctx, key.data(), iv.data());
  uint8_t* ciphertext_ptr = (uint8_t*)&str[AES_KEYLEN + 2 * AES_BLOCKLEN];
#endif

  // Decrypt first block to get size
  Block size_block;
  memcpy(&size_block, ciphertext_ptr - AES_BLOCKLEN, AES_BLOCKLEN);
  AES_decrypt_buf(&ctx, size_block.data(), AES_BLOCKLEN);
  size_t ret_size = *(size_t*)size_block.data();

  size_t bonus = AES_BLOCKLEN - (ret_size % 16);

  std::string ret;
  ret.resize(ret_size + bonus);


  uint8_t* message_ptr = (uint8_t*)&ret[0];
  #ifdef CTR
  memcpy(message_ptr, ciphertext_ptr, ret_size);
  #else
  memcpy(message_ptr, ciphertext_ptr, ret.size());
  #endif
  AES_decrypt_buf(&ctx, message_ptr, ret.size());

  ret.resize(ret_size);
  return ret;
}

#endif  // EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_CRYPTO_H_
