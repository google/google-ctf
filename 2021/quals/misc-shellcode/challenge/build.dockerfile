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

FROM arm64v8/ubuntu:20.04 as build_arm

RUN apt-get update && apt-get install -yq --no-install-recommends build-essential

RUN mkdir /build
COPY chal.c /build/
RUN gcc -o /build/chal-aarch64 /build/chal.c

FROM ubuntu:20.04 as build

RUN apt-get update && apt-get install -yq --no-install-recommends build-essential

RUN mkdir /build
COPY chal.c /build/
RUN gcc -o /build/chal-x86-64 /build/chal.c
COPY --from=build_arm /build/chal-aarch64 /build/
COPY --from=build_arm /lib/aarch64-linux-gnu/libc.so.6 /build/libc-aarch64.so

CMD sleep 1
