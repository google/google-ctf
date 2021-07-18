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

set -e -x -v

build_dir="${1}"

cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")"

g++ -g -O1 --std=c++17 -DCTR=1 -DBADSTUFF_3=1 -DBADDATA_1=1 -DRAND_3=1 -DDEFENSE_5=1 -z execstack polymorph.cc crypto.cc aes.cc defenses.obj -o "${build_dir}/polymorph"
clang++ -g --std=c++17 -DCTR=1 -DRAND_3=1 pack_dir.cc crypto.cc aes.cc -o "${build_dir}/pack_dir"
"${1}/pack_dir" pack ./ > "${build_dir}/packed_bytes"
python3 ./patchbytes.py "${build_dir}/polymorph" sxrpzr "${build_dir}/packed_bytes"
