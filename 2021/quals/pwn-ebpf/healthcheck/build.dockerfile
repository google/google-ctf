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
	build-essential

RUN mkdir /build
WORKDIR /build
COPY exploit.c /build/
RUN gcc -static -o p exploit.c && tar -j -cf p.tar.bz2 p
