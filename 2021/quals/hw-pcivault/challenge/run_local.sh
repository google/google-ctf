#!/usr/bin/env bash
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

set -Eeuxo pipefail

HASH=fa1d3cf7a8aa088bccec13afd5122aadbdb277b466f7ec81b92c027f0a12140428e99450502a4eae6da1320177f75a260f2e6eccd216667b415e66f26e5dc71d

if ! sha512sum --status -c <(echo "${HASH}  docker.tar.gz"); then
    rm docker.tar.gz 2>/dev/null || true
    wget "https://storage.googleapis.com/gctf-2021-attachments-project/${HASH}" -O docker.tar.gz
    zcat docker.tar.gz | docker load
fi

docker run --privileged -p 127.0.0.1:1337:1337/tcp --rm -it pcivault-player-image
