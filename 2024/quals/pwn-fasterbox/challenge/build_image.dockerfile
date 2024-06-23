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
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Zurich
RUN apt-get update && apt-get install -yq --no-install-recommends \
  build-essential \
  ca-certificates \
  cmake \
  curl \
  ninja-build

RUN mkdir /build
RUN mkdir /src

RUN curl -o /src/bpf-helper.h https://raw.githubusercontent.com/google/sandboxed-api/cf43c0f02ccd6f1da274ef4c77495e4620830133/sandboxed_api/sandbox2/util/bpf_helper.h
COPY CMakeLists.txt /src/
COPY chal.cc /src/

RUN cmake -G Ninja -B build src && ninja -C /build

FROM ubuntu:24.04 as image
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Zurich
RUN apt-get update && apt-get install -yq --no-install-recommends \
  init \
  socat

COPY --from=build /build/chal /root/
COPY flag /root/
COPY chal.service chal.target /usr/lib/systemd/system/
COPY chal.sh /root/
RUN chown root:root /root/chal /root/chal.sh

FROM ubuntu:24.04 as image_creator
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -yq --no-install-recommends \
  squashfs-tools

RUN mkdir /build
WORKDIR /build
COPY --from=image / /src
RUN mksquashfs /src rootfs.img
