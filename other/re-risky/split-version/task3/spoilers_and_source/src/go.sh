#!/bin/bash
# Copyright 2018 Google LLC
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
set -e

python gen_mixer.py

gcc -Wall -Wextra checker.c -o checker.o -nostdlib -c -O0 \
    -fno-exceptions -fno-asynchronous-unwind-tables
ld checker.o -o checker -e ep_checker -Ttext 0x42000000 -z max-page-size=0x1000
objdump -x checker

python gen_gold.py

echo "Check false"
python gold.py 'xxxxxxx' && ( echo 'ERROR (wrong flag)'; false )

echo "Check true"
python gold.py 'flag{MixingOfGoldenBits}' || ( echo 'ERROR (correct flag)'; false )

echo All OK.
