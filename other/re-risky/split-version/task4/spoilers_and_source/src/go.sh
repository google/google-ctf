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

python gen_carbon.py

riscv64-unknown-elf-gcc -Wall -Wextra carbon.c -o carbon

echo "Check false"
spike pk carbon 'wrongflag' && ( echo 'ERROR (wrong flag)'; false )

echo "Check true"
spike pk carbon 'flag{PrettyRiskvChallenge}' || ( echo 'ERROR (correct flag)'; false )

echo All OK.


