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
FROM ubuntu:20.04 as build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -yq --no-install-recommends \
    wget \
    kmod

COPY kconcat.ko /
COPY init /
RUN mkdir -p /etc/kconcat/message-templates && echo "No pwning is allowed here!" > /etc/kconcat/message-templates/nopwning
RUN ln -s /dev/vdb /flag

# Fix the permissions for the files we're copying in
RUN chown -R 0:0 /kconcat.ko /init && \
	chmod +x /init

RUN useradd -s /bin/bash ctf