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
FROM ubuntu:18.04

WORKDIR /build

# Install any needed packages specified in requirements.txt
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
      build-essential \
      cmake \
      bzip2 \
      wget && \
    apt-get clean

RUN mkdir -p /build/keygen/third_party
ADD third_party/PQClean /build/keygen/third_party/PQClean
COPY flag keygen/CMakeLists.txt keygen/main.cc /build/keygen/

RUN cd /build/keygen && \
    cmake . && \
    make

RUN cd /build/keygen && \
    ./keygen flag 200 encaps.json

RUN gzip -c /build/keygen/encaps.json > /build/keygen/encaps.json.gz

CMD sleep 1
