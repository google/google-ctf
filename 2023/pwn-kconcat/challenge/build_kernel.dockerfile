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

RUN mkdir -p /build
WORKDIR /build

RUN git clone -n https://github.com/thejh/linux
WORKDIR /build/linux
RUN git fetch origin 3bd859b0eb1fb840cad49d3c402e193b169d6ae3 && git checkout 3bd859b0eb1fb840cad49d3c402e193b169d6ae3
RUN make defconfig

COPY kernelctf.config /build/linux/kernel/configs
RUN make kernelctf.config

RUN make -j`nproc`

COPY kconcat_module/. /build/kconcat_module/
WORKDIR /build/kconcat_module
RUN make -C ../linux M=$PWD
