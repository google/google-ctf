#!/bin/bash
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Sajjad "JJ" Arshad (sajjadium)

docker build -t tridroid -f Dockerfile . || exit 1
docker rm tridroid 2> /dev/null
docker run -d --name tridroid -it -p 1337:1337 --privileged -v /dev/kvm:/dev/kvm tridroid || exit 1
echo -e "\nServer is running on localhost:1337, ctrl+c to exit"
docker attach tridroid
