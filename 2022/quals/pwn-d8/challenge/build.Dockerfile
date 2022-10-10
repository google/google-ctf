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
RUN cd /build && fetch v8 && cd v8 && git checkout 581a5ef7be2d340b4a0795a3b481ff7668e2252a && gclient sync

COPY v8.patch /build

RUN cd /build/v8 && patch -p1 < /build/v8.patch && \
    gn gen out/release --args='is_debug=false target_cpu="x64"' && \
    autoninja -C out/release challenge
