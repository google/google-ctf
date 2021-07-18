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

FROM registry.gitlab.com/qemu-project/qemu/qemu/debian-hexagon-cross:latest as build

RUN mkdir /build
COPY build.makefile /build/Makefile
COPY first.s /build
COPY main.s /build
COPY gen_hex_funcs.py /build
RUN make -C /build challenge

CMD sleep 1
