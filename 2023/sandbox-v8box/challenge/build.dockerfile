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

# Not ubuntu because I was having issues with the snap store ¯\_(ツ)_/¯
FROM debian:testing

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir -p /build/v8
WORKDIR /build

RUN apt update && apt install -yq --no-install-recommends \
    git \
    python3 \
    ca-certificates \
    curl \
    tar \
    xz-utils \
    build-essential \
    lsb-release \
    sudo \
    file

# Get depot_tools
RUN git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
ENV PATH=/build/depot_tools:$PATH
RUN gclient

# Check out the V8 source code
RUN cd /build/v8 && fetch v8

WORKDIR /build/v8/v8
RUN ./build/install-build-deps.sh

RUN git fetch && git switch -d d90d4533b05301e2be813a5f90223f4c6c1bf63d && gclient sync

COPY v8.patch /build/
COPY 0001-Protect-chunk-headers-on-the-heap.patch /build/
RUN chmod 644 /build/v8.patch /build/0001-Protect-chunk-headers-on-the-heap.patch
RUN git apply < /build/v8.patch
RUN git apply < /build/0001-Protect-chunk-headers-on-the-heap.patch

RUN ./tools/dev/v8gen.py x64.release
COPY args.gn out.gn/x64.release/args.gn
RUN chmod 644 out.gn/x64.release/args.gn
RUN gn gen out.gn/x64.release

RUN ninja -C out.gn/x64.release d8
