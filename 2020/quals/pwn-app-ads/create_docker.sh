#!/bin/bash
# Copyright 2020 Google LLC
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


cd `dirname $0`

docker stop pwn-android
docker rm pwn-android
#docker rmi pwn-android
docker build . -f Dockerfile -t pwn-android
docker create \
  --name=pwn-android \
  --env COLUMNS=`tput cols` \
  --env LINES=`tput lines` \
  --privileged \
  -i -t pwn-android

