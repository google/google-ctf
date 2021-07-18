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

# Debian testing, make sure that it's using the correct version of everything
FROM debian@sha256:8bcf7309e62b04a640d5efa95d34c982b74933a80f46d8046ac6c5d732793eea
RUN echo 'deb http://snapshot.debian.org/archive/debian/20210511T000000Z testing main' > /etc/apt/sources.list

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update -o Acquire::Check-Valid-Until=false && apt install -yq --no-install-recommends \
	build-essential \
	flex \
	bison \
	wget \
	bc \
	ca-certificates \
	libelf-dev \
	libssl-dev

RUN mkdir -p /build /build/kernel_module
WORKDIR /build
COPY kernel.config /build/

RUN wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.12.9.tar.xz && \
	tar -xf linux-5.12.9.tar.xz && \
	mv linux-5.12.9 linux && \
	cd linux && \
	cp ../kernel.config .config && \
	make -j`nproc`

COPY kernel_module/ctf.c kernel_module/Kbuild /build/kernel_module/
RUN cd /build/kernel_module && make -C ../linux M=$PWD
