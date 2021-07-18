# Copyright 2021 Google LLC
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

FROM ubuntu:20.04 as build

RUN apt-get update && apt-get install -yq --no-install-recommends build-essential git ca-certificates clang premake4 sdcc python3 python3-pip
RUN pip3 install pycryptodome

RUN mkdir /build
RUN git clone https://github.com/redcode/Z /build/Z
RUN git clone https://github.com/redcode/Z80 /build/Z80
RUN git clone https://github.com/arkku/ihex /build/ihex
RUN git clone https://github.com/kokke/tiny-AES-c.git /build/tiny-AES-c
COPY src/ /build/
RUN make -C /build 

CMD sleep 1
