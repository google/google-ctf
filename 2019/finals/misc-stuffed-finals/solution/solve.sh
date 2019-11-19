#!/bin/bash

# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

# sudo apt install cmake

# This assumes curl will not try to decompress the file automatically. For me
# curl doesn't decompress automatically.
curl https://stuffed.web.ctfcompetition.com/ -H 'Accept-Encoding: br' > bomb.br

# Nothing special about this specific version, we just want some specific version.
wget https://github.com/google/brotli/archive/c435f066751ef83aa4194445085a70ad9d193704.zip
unzip c435f066751ef83aa4194445085a70ad9d193704.zip
cd brotli-c435f066751ef83aa4194445085a70ad9d193704

patch c/dec/decode.c ../reduce_repeats.patch

mkdir out; cd out
# --disable-debug reduces runtime from 6.7s to 2.8s.
# Although it increases compile time from 10.1s to 19.0s.
../configure-cmake --disable-debug
make

./brotli -dc ../../bomb.br | grep CTF
