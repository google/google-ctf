# Copyright 2023 Google LLC
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

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Zurich
RUN apt-get update && apt-get install -yq --no-install-recommends build-essential \
  cmake git ca-certificates linux-libc-dev ninja-build \
  python3 python3-pip libclang-dev libcap-dev

RUN mkdir /build
RUN mkdir /src

# Cache Sandboxed API build
RUN echo "int main() {}" > /src/chal.cc
COPY CMakeLists_sapi.txt /src/CMakeLists.txt
RUN cmake -G Ninja -B build src
RUN ninja -C /build

COPY CMakeLists.txt /src/
COPY chal.cc /src/
RUN touch /src/CMakeLists.txt
RUN touch /src/chal.cc
RUN ninja -C /build
RUN strip /build/chal

CMD sleep 1
