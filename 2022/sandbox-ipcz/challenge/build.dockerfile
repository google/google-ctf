# Copyright 2022 Google LLC
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

# install required deps
RUN apt-get update && apt-get -y upgrade
RUN apt-get install -yq --no-install-recommends build-essential git ca-certificates python3-pkgconfig curl python3

# install depot_tools
RUN git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git /opt/depot_tools
ENV PATH="/opt/depot_tools:${PATH}"

RUN mkdir /build
RUN git clone https://github.com/krockot/ipcz.git /build/ipcz && cd /build/ipcz && git checkout 6a6ebe43c2cb86882b0df9bf888dc5d34037f015
RUN cd /build/ipcz && cp .gclient-default .gclient && gclient sync

COPY 0001-Allow-embedder-to-choose-node-name.patch 0002-Remove-locking-code.patch 0003-Add-build-targets-for-challenge-binaries.patch /build/
RUN cd /build/ipcz && git apply ../0001-Allow-embedder-to-choose-node-name.patch ../0002-Remove-locking-code.patch ../0003-Add-build-targets-for-challenge-binaries.patch

RUN mkdir /build/ipcz/src/challenge/
COPY broker.cc flag_bearer.cc BUILD.gn /build/ipcz/src/challenge/

RUN cd /build/ipcz/ && gn gen out && ninja -C out challenge

CMD /bin/true
