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

RUN apt-get update && apt-get install -yq --no-install-recommends build-essential libprotobuf-dev protobuf-compiler libcap-dev

RUN mkdir /build
COPY chal.cc init.c chal.proto /build/
COPY build.Makefile /build/Makefile
RUN make -C /build chal init

CMD /bin/true
