// //////////////////////////////////////////////////////////
// hmac.h
// Copyright (c) 2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#pragma once

// based on http://tools.ietf.org/html/rfc2104
// see also http://en.wikipedia.org/wiki/Hash-based_message_authentication_code

/** Usage:
    std::string msg = "The quick brown fox jumps over the lazy dog";
    std::string key = "key";
    std::string md5hmac  = hmac< MD5  >(msg, key);
    std::string sha1hmac = hmac< SHA1 >(msg, key);
    std::string sha2hmac = hmac<SHA256>(msg, key);

    Note:
    To keep my code simple, HMAC computation currently needs the whole message at once.
    This is in contrast to the hashes MD5, SHA1, etc. where an add() method is available
    for incremental computation.
    You can use any hash for HMAC as long as it provides:
    - constant HashMethod::BlockSize (typically 64)
    - constant HashMethod::HashBytes (length of hash in bytes, e.g. 20 for SHA1)
    - HashMethod::add(buffer, bufferSize)
    - HashMethod::getHash(unsigned char buffer[HashMethod::BlockSize])
  */

#include <string>
#include <cstring> // memcpy

/// compute HMAC hash of data and key using MD5, SHA1 or SHA256
template <typename HashMethod>
std::string hmac(const void* data, size_t numDataBytes, const void* key, size_t numKeyBytes)
{
  // initialize key with zeros
  unsigned char usedKey[HashMethod::BlockSize] = {0};

  // adjust length of key: must contain exactly blockSize bytes
  if (numKeyBytes <= HashMethod::BlockSize)
  {
    // copy key
    memcpy(usedKey, key, numKeyBytes);
  }
  else
  {
    // shorten key: usedKey = hashed(key)
    HashMethod keyHasher;
    keyHasher.add(key, numKeyBytes);
    keyHasher.getHash(usedKey);
  }

  // create initial XOR padding
  for (size_t i = 0; i < HashMethod::BlockSize; i++)
    usedKey[i] ^= 0x36;

  // inside = hash((usedKey ^ 0x36) + data)
  unsigned char inside[HashMethod::HashBytes];
  HashMethod insideHasher;
  insideHasher.add(usedKey, HashMethod::BlockSize);
  insideHasher.add(data,    numDataBytes);
  insideHasher.getHash(inside);

  // undo usedKey's previous 0x36 XORing and apply a XOR by 0x5C
  for (size_t i = 0; i < HashMethod::BlockSize; i++)
    usedKey[i] ^= 0x5C ^ 0x36;

  // hash((usedKey ^ 0x5C) + hash((usedKey ^ 0x36) + data))
  HashMethod finalHasher;
  finalHasher.add(usedKey, HashMethod::BlockSize);
  finalHasher.add(inside,  HashMethod::HashBytes);

  return finalHasher.getHash();
}


/// convenience function for std::string
template <typename HashMethod>
std::string hmac(const std::string& data, const std::string& key)
{
  return hmac<HashMethod>(data.c_str(), data.size(), key.c_str(), key.size());
}
