#!/bin/bash

# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Author: Ian Eldred Pudney

set -e -x
g++ --std=c++17 build_public_hashes.cc sha256.cpp -o build_public_hashes
./build_public_hashes ../../attachments/malware ../../attachments/safe > public_hashes.h

g++ --std=c++17 -O3 gather_one_bit.cc sha256.cpp -o gather_bit_0 -DTARGET_BIT=0
g++ --std=c++17 -O3 gather_one_bit.cc sha256.cpp -o gather_bit_1 -DTARGET_BIT=1
g++ --std=c++17 -O3 gather_one_bit.cc sha256.cpp -o gather_bit_2 -DTARGET_BIT=2
g++ --std=c++17 -O3 gather_one_bit.cc sha256.cpp -o gather_bit_3 -DTARGET_BIT=3
g++ --std=c++17 -O3 gather_one_bit.cc sha256.cpp -o gather_bit_4 -DTARGET_BIT=4
g++ --std=c++17 -O3 gather_one_bit.cc sha256.cpp -o gather_bit_5 -DTARGET_BIT=5
g++ --std=c++17 -O3 gather_one_bit.cc sha256.cpp -o gather_bit_6 -DTARGET_BIT=6
g++ --std=c++17 -O3 gather_one_bit.cc sha256.cpp -o gather_bit_7 -DTARGET_BIT=7
g++ --std=c++17 -O3 gather_one_bit.cc sha256.cpp -o gather_bit_8 -DTARGET_BIT=8
g++ --std=c++17 -O3 gather_one_bit.cc sha256.cpp -o gather_bit_9 -DTARGET_BIT=9
g++ --std=c++17 -O3 gather_one_bit.cc sha256.cpp -o gather_bit_10 -DTARGET_BIT=10
g++ --std=c++17 -O3 gather_one_bit.cc sha256.cpp -o gather_bit_11 -DTARGET_BIT=11
g++ --std=c++17 -O3 gather_one_bit.cc sha256.cpp -o gather_bit_12 -DTARGET_BIT=12
g++ --std=c++17 -O3 gather_one_bit.cc sha256.cpp -o gather_bit_13 -DTARGET_BIT=13
g++ --std=c++17 -O3 gather_one_bit.cc sha256.cpp -o gather_bit_14 -DTARGET_BIT=14
g++ --std=c++17 -O3 gather_one_bit.cc sha256.cpp -o gather_bit_15 -DTARGET_BIT=15

g++ --std=c++17 output_reader.cc -o output_reader

printf "#include <map>\n#include <string>\n\n" > hash_pieces.h

../../upload_for_scoring.py ./gather_bit_0 polymorph.2021.ctfcompetition.com 1337 | ./output_reader 0 >> hash_pieces.h
../../upload_for_scoring.py ./gather_bit_1 polymorph.2021.ctfcompetition.com 1337 | ./output_reader 1 >> hash_pieces.h
../../upload_for_scoring.py ./gather_bit_2 polymorph.2021.ctfcompetition.com 1337 | ./output_reader 2 >> hash_pieces.h
../../upload_for_scoring.py ./gather_bit_3 polymorph.2021.ctfcompetition.com 1337 | ./output_reader 3 >> hash_pieces.h
../../upload_for_scoring.py ./gather_bit_4 polymorph.2021.ctfcompetition.com 1337 | ./output_reader 4 >> hash_pieces.h
../../upload_for_scoring.py ./gather_bit_5 polymorph.2021.ctfcompetition.com 1337 | ./output_reader 5 >> hash_pieces.h
../../upload_for_scoring.py ./gather_bit_6 polymorph.2021.ctfcompetition.com 1337 | ./output_reader 6 >> hash_pieces.h
../../upload_for_scoring.py ./gather_bit_7 polymorph.2021.ctfcompetition.com 1337 | ./output_reader 7 >> hash_pieces.h
../../upload_for_scoring.py ./gather_bit_8 polymorph.2021.ctfcompetition.com 1337 | ./output_reader 8 >> hash_pieces.h
../../upload_for_scoring.py ./gather_bit_9 polymorph.2021.ctfcompetition.com 1337 | ./output_reader 9 >> hash_pieces.h
../../upload_for_scoring.py ./gather_bit_10 polymorph.2021.ctfcompetition.com 1337 | ./output_reader 10 >> hash_pieces.h
../../upload_for_scoring.py ./gather_bit_11 polymorph.2021.ctfcompetition.com 1337 | ./output_reader 11 >> hash_pieces.h
../../upload_for_scoring.py ./gather_bit_12 polymorph.2021.ctfcompetition.com 1337 | ./output_reader 12 >> hash_pieces.h
../../upload_for_scoring.py ./gather_bit_13 polymorph.2021.ctfcompetition.com 1337 | ./output_reader 13 >> hash_pieces.h
../../upload_for_scoring.py ./gather_bit_14 polymorph.2021.ctfcompetition.com 1337 | ./output_reader 14 >> hash_pieces.h
../../upload_for_scoring.py ./gather_bit_15 polymorph.2021.ctfcompetition.com 1337 | ./output_reader 15 >> hash_pieces.h

g++ --std=c++17 solution.cc sha256.cpp -o solution
../../upload_for_scoring.py ./solution polymorph.2021.ctfcompetition.com 1337
