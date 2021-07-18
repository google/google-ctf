// minimal test case for https://github.com/stbrumme/hash-library/issues/2
// g++ github-issue2.cpp ../sha*.cpp ../keccak.cpp ../md5.cpp -o github-issue2 && ./github-issue2

#include "../sha1.h"
#include "../sha256.h"
#include "../sha3.h"
#include "../keccak.h"
#include "../md5.h"
#include <iostream>

int main()
{
  std::string text = "hello world";

  std::cout << "SHA1:" << std::endl;
  SHA1 sha1;
  sha1.add(text.c_str(), text.size());

  std::cout << sha1.getHash() << std::endl;
  std::cout << sha1.getHash() << std::endl;
  std::cout << sha1.getHash() << std::endl;

  std::cout << std::endl;

  std::cout << "SHA256:" << std::endl;
  SHA256 sha256;
  sha256.add(text.c_str(), text.size());

  std::cout << sha256.getHash() << std::endl;
  std::cout << sha256.getHash() << std::endl;
  std::cout << sha256.getHash() << std::endl;

  std::cout << std::endl;

  std::cout << "SHA3:" << std::endl;
  SHA3 sha3;
  sha3.add(text.c_str(), text.size());

  std::cout << sha3.getHash() << std::endl;
  std::cout << sha3.getHash() << std::endl;
  std::cout << sha3.getHash() << std::endl;

  std::cout << std::endl;

  std::cout << "Keccak:" << std::endl;
  Keccak keccak;
  keccak.add(text.c_str(), text.size());

  std::cout << keccak.getHash() << std::endl;
  std::cout << keccak.getHash() << std::endl;
  std::cout << keccak.getHash() << std::endl;

  std::cout << std::endl;

  std::cout << "MD5:" << std::endl;
  MD5 md5;
  md5.add(text.c_str(), text.size());

  std::cout << md5.getHash() << std::endl;
  std::cout << md5.getHash() << std::endl;
  std::cout << md5.getHash() << std::endl;

  return 0;
}
