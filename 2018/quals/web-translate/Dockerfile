# Copyright 2018 Google LLC
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

FROM debian

ENV LANG C.UTF-8
ENV LANGUAGE C.UTF-8
ENV LC_ALL C.UTF-8

# Add user www
RUN set -e -x; \
  groupadd -g 1337 www; \
  useradd -g 1337 -u 1337 -m www

# Install deps
RUN apt-get update
RUN apt-get install -y curl gnupg sudo memcached supervisor strace
RUN curl -sL https://deb.nodesource.com/setup_8.x | bash -
RUN apt-get update
RUN apt-get install -y nodejs && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Get the CTF files there
ADD chall /usr/local/chall
RUN chown -R root:root /usr/local/chall
RUN chmod -R 0655 /usr/local/chall

# Setup npm
WORKDIR /usr/local/chall
RUN npm install

# We remove the 'use strict' in VM2 sandboxes, to let Domino run in there.
# The version is pinned just in case.
RUN sed -i "61s/'use strict';//" /usr/local/chall/node_modules/vm2/lib/sandbox.js #yolo

# Downgrade to www and run
USER www
WORKDIR /usr/local/chall
CMD memcached -d -m 1024 && node ./srcs/server.js