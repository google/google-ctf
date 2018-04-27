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



docker rm re-johnny-boy-build-cont
docker build --build-arg flag='CTF{J0hnny_R3memb3rs}' -t re-johnny-boy-build-img .
docker create --name re-johnny-boy-build-cont re-johnny-boy-build-img
docker cp re-johnny-boy-build-cont:/tmp/build/ ./artifacts/
docker rm re-johnny-boy-build-cont
# Uncomment to upload.
# python reset.py ; sleep 2; avrdude -v -patmega32u4 -cavr109 -P /dev/ttyACM0 -b57600 -D -Uflash:w:artifacts/build/chall.ino.hex:i
