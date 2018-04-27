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



#!/bin/bash
make generator primary
rm -f output
for i in $(seq 50)
do
  { ./generator | stdbuf -o 0 ./primary --silent ;} >> output 2>&1
done

if ! grep "CTF{.*}" output
then
  echo "Couldn't get flag :("
  exit 1
else
  exit 0
fi

