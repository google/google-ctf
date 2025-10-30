# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM node:20-alpine as puppeteer
ENV PUPPETEER_SKIP_DOWNLOAD=true
ENV PUPPETEER_CACHE_DIR=/home/node/puppeteer_cache

WORKDIR /home/node/
COPY src/package.json /home/node/
RUN npm i && npx puppeteer browsers install chrome

FROM gcr.io/kctf-docker/challenge@sha256:9f15314c26bd681a043557c9f136e7823414e9e662c08dde54d14a6bfd0b619f
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    # Node.js
    nodejs \
    # Chromium/Puppeteer dependencies
    ca-certificates \
    fonts-liberation \
    libasound2t64 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcairo2 \
    libcups2 \
    libdbus-1-3 \
    libexpat1 \
    libgbm1 \
    libglib2.0-0 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libpango-1.0-0 \
    libx11-6 \
    libxcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxrandr2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=puppeteer /home/node/puppeteer_cache /home/user/puppeteer_cache/
COPY --from=puppeteer /home/node/node_modules /home/user/node_modules/
COPY src/ /home/user/
COPY start.sh /home/user

CMD kctf_setup && \
    mount -t tmpfs none /tmp && \
    mkdir /tmp/chrome-userdata && chmod o+rwx /tmp/chrome-userdata && \
    kctf_drop_privs env FLAG="${FLAG}" PUPPETEER_CACHE_DIR="/home/user/puppeteer_cache" /home/user/start.sh
