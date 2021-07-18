// //////////////////////////////////////////////////////////
// digest.cpp
// Copyright (c) 2014,2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

// g++ -O3 digest.cpp crc32.cpp md5.cpp sha1.cpp sha256.cpp keccak.cpp sha3.cpp -o digest

#include "crc32.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "keccak.h"
#include "sha3.h"

#include <iostream>
#include <fstream>

int main(int argc, char** argv)
{
  // syntax check
  if (argc < 2 || argc > 3)
  {
    std::cout << "./digest filename [--crc|--md5|--sha1|--sha256|--keccak|--sha3]" << std::endl;
    return 1;
  }

  // parameters
  std::string filename  = argv[1];
  std::string algorithm = argc == 3 ? argv[2] : "";
  bool computeCrc32     = algorithm.empty() || algorithm == "--crc";
  bool computeMd5       = algorithm.empty() || algorithm == "--md5";
  bool computeSha1      = algorithm.empty() || algorithm == "--sha1";
  bool computeSha2      = algorithm.empty() || algorithm == "--sha2" || algorithm == "--sha256";
  bool computeKeccak    = algorithm.empty() || algorithm == "--keccak";
  bool computeSha3      = algorithm.empty() || algorithm == "--sha3";

  CRC32  digestCrc32;
  MD5    digestMd5;
  SHA1   digestSha1;
  SHA256 digestSha2;
  Keccak digestKeccak(Keccak::Keccak256);
  SHA3   digestSha3  (SHA3  ::Bits256);

  // each cycle processes about 1 MByte (divisible by 144 => improves Keccak/SHA3 performance)
  const size_t BufferSize = 144*7*1024;
  char* buffer = new char[BufferSize];

  // select input source: either file or standard-in
  std::ifstream file;
  std::istream* input = NULL;
  // accept std::cin, syntax will be: "./digest - --sha3 < data"
  if (filename == "-")
  {
    input = &std::cin;
  }
  else
  {
    // open file
    file.open(filename.c_str(), std::ios::in | std::ios::binary);
    if (!file)
    {
      std::cerr << "Can't open '" << filename << "'" << std::endl;
      return 2;
    }

    input = &file;
  }

  // process file
  while (*input)
  {
    input->read(buffer, BufferSize);
    std::size_t numBytesRead = size_t(input->gcount());

    if (computeCrc32)
      digestCrc32 .add(buffer, numBytesRead);
    if (computeMd5)
      digestMd5   .add(buffer, numBytesRead);
    if (computeSha1)
      digestSha1  .add(buffer, numBytesRead);
    if (computeSha2)
      digestSha2  .add(buffer, numBytesRead);
    if (computeKeccak)
      digestKeccak.add(buffer, numBytesRead);
    if (computeSha3)
      digestSha3  .add(buffer, numBytesRead);
  }

  // clean up
  file.close();
  delete[] buffer;

  // show results
  if (computeCrc32)
    std::cout << "CRC32:      " << digestCrc32 .getHash() << std::endl;
  if (computeMd5)
    std::cout << "MD5:        " << digestMd5   .getHash() << std::endl;
  if (computeSha1)
    std::cout << "SHA1:       " << digestSha1  .getHash() << std::endl;
  if (computeSha2)
    std::cout << "SHA2/256:   " << digestSha2  .getHash() << std::endl;
  if (computeKeccak)
    std::cout << "Keccak/256: " << digestKeccak.getHash() << std::endl;
  if (computeSha3)
    std::cout << "SHA3/256:   " << digestSha3  .getHash() << std::endl;

  return 0;
}
