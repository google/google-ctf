// minimal test case for https://github.com/stbrumme/hash-library/issues/6
// g++ github-issue6.cpp ../sha3.cpp -o github-issue6 && ./github-issue6

#include "../sha3.h"
#include <iostream>

int main(int argc, char *argv[])
{
  std::string text = "72a5f501151ca974002f34";

  SHA3 hasher(SHA3::Bits512);
  hasher.add(text.data(), text.size());
  std::cout << hasher.getHash() << std::endl;

  return 0;
}
