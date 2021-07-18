# Portable C++ Hashing Library

This is a mirror of my library hosted at https://create.stephan-brumme.com/hash-library/

In a nutshell:

- computes CRC32, MD5, SHA1 and SHA256 (most common member of the SHA2 functions), Keccak and its SHA3 sibling
- optional HMAC (keyed-hash message authentication code)
- no external dependencies, small code size
- can work chunk-wise (for example when reading streams block-by-block)
- portable: supports Windows and Linux, tested on Little Endian and Big Endian CPUs
- roughly as fast as Linux core hashing functions
- open source, zlib license

You can find code examples, benchmarks and much more on my website https://create.stephan-brumme.com/hash-library/

# How to use

This example computes SHA256 hashes but the API is more or less identical for all hash algorithms:

``` cpp
// SHA2 test program
#include "sha256.h"
#include <iostream> // for std::cout only, not needed for hashing library

int main(int, char**)
{
  // create a new hashing object
  SHA256 sha256;

  // hashing an std::string
  std::cout << sha256("Hello World") << std::endl;
  // => a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e

  // hashing a buffer of bytes
  const char* buffer = "How are you";
  std::cout << sha256(buffer, 11) << std::endl;
  // => 9c7d5b046878838da72e40ceb3179580958df544b240869b80d0275cc07209cc

  // or in a streaming fashion (re-use "How are you")
  SHA256 sha256stream;
  const char* url = "create.stephan-brumme.com"; // 25 bytes
  int step = 5;
  for (int i = 0; i < 25; i += step)
    sha256stream.add(url + i, step); // add five bytes at a time
  std::cout << sha256stream.getHash() << std::endl;
  // => 82aa771f1183c52f973c798c9243a1c73833ea40961c73e55e12430ec77b69f6

  return 0;
}
```
