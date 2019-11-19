# Copyright 2019 Google LLC
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

FROM ubuntu:19.04

RUN apt update && apt upgrade -y

RUN apt-get install -y \
    autoconf \
    bison \
    flex \
    gcc \
    g++ \
    git \
    libprotobuf-dev \
    libnl-route-3-dev \
    libtool \
    make \
    pkg-config \
    protobuf-compiler

RUN cd / && git clone https://github.com/google/nsjail.git && \
    cd /nsjail && make && mv /nsjail/nsjail /root && rm -rf -- /nsjail

RUN set -e -x; \
        groupadd -g 1338 user; \
        useradd -g 1338 -u 1338 -m user

COPY challenge/main /root/
COPY challenge/helper /root/
COPY flag /root/

RUN set -e -x; \
    chown -R user:user /root; \
    chmod 700 /root; \
    chmod 700 /root/main; \
    chmod 700 /root/helper; \
    chmod 700 /root/flag; \
    chmod 700 /root/nsjail

USER user
CMD cd /root && ./main
