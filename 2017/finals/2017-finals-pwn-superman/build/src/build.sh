#!/bin/bash -eu
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.



#!/bin/sh

set -ex

cd /shared/out

PWNLIB_NOTERM=1 python ../src/generate.py

cd $HOME/qemu

git config --global user.name "Zach Riggle"
git config --global user.email "riggle@google.com"

for patch in /shared/src/*.patch; do
    git am "$patch"
done

./configure --target-list=arm-linux-user --static --enable-linux-user --disable-system
make CFLAGS="-Wno-unused-function -Wno-unused-variable -Wno-unused-label"

cp arm-linux-user/qemu-arm /shared/out/

gcc -static /shared/src/close.c -o /shared/out/close
