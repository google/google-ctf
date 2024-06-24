# Copyright 2024 Google LLC
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
FROM ubuntu:24.04 as build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -yq --no-install-recommends \
        git \
        build-essential \
        flex \
        bison \
        wget \
        bc \
        ca-certificates \
        libelf-dev \
        libssl-dev \
        python3 \
        cpio

RUN mkdir -p /build/linux
WORKDIR /build/linux

RUN git init && \
    git remote add origin https://github.com/torvalds/linux.git && \
    git fetch --depth 1 origin e0cce98fe279b64f4a7d81b7f5c3a23d80b92fbc && \
    git checkout FETCH_HEAD

COPY kconfig /build/linux/.config

RUN make -j`nproc`
