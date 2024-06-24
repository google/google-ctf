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

FROM debian:stable

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

RUN git fetch && git switch -d 'f603d5769be54dcd24308ff9aec041486ea54f5b^'
RUN rm -Rf ../.cipd; gclient sync

COPY v8.patch /build/
RUN git apply < /build/v8.patch

RUN mkdir -p out/x64.release
COPY args.gn out/x64.release/args.gn
RUN chmod 644 out/x64.release/args.gn
RUN gn gen out/x64.release

RUN autoninja -C out/x64.release d8
