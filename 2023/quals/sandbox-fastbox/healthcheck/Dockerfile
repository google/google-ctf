# Copyright 2023 Google LLC
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

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Zurich
RUN apt-get update && apt-get install -yq --no-install-recommends \
    ca-certificates \
    curl \
    make \
    patch \
    unzip \
    wget

ENV PROTOC_ZIP=protoc-23.0-linux-x86_64.zip
RUN curl -OL https://github.com/protocolbuffers/protobuf/releases/download/v23.0/$PROTOC_ZIP \
    && unzip -o $PROTOC_ZIP -d /usr/local bin/protoc \
    && unzip -o $PROTOC_ZIP -d /usr/local 'include/*' \ 
    && rm -f $PROTOC_ZIP

RUN mkdir /build
COPY Makefile_proto /build/Makefile
RUN make -C /build

FROM gcr.io/kctf-docker/healthcheck@sha256:61b36c73b498a682fef82fa5cb088330729cb110b0847e6bdf30aa9825da9279

RUN apt-get update && apt-get -yq --no-install-recommends install python3-pip && python3 -m pip install protobuf && apt-get remove --purge -y python3-pip

RUN apt-get update && apt-get -yq --no-install-recommends install build-essential

RUN mkdir /home/user/exploit
COPY exploit/exploit.py /home/user/exploit/
COPY --from=build /build/sandboxed_api /home/user/exploit/sandboxed_api
COPY healthcheck_loop.sh healthcheck.py healthz_webserver.py /home/user/

CMD kctf_drop_privs /home/user/healthcheck_loop.sh & /home/user/healthz_webserver.py
