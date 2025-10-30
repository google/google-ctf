# Copyright 2025 Google LLC
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

# Note: when testing locally, you may have to run this Dockerfile with
#   docker run --privileged ...
# for example:
#   docker run --privileged --name lost-in-transliteration -it --rm -p 1337:1337 $(docker build -q .) 

FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine@sha256:abee55b11f42473da7a512149a4c1e48f5a1248533614f7e88f29de7ebd3411d AS build
WORKDIR /build
COPY challenge.csproj Program.cs ./
RUN dotnet restore
RUN dotnet publish -o out

FROM node:18-alpine@sha256:8d6421d663b4c28fd3ebc498332f249011d118945588d0a35cb9bc4b8ca09d9e AS puppeteer
ENV PUPPETEER_SKIP_DOWNLOAD=true
ENV PUPPETEER_CACHE_DIR=/home/node/puppeteer_cache
WORKDIR /home/node
COPY package.json package-lock.json /home/node/
RUN npm ci && npx puppeteer browsers install chrome@136.0.7103.94

FROM gcr.io/kctf-docker/challenge@sha256:9f15314c26bd681a043557c9f136e7823414e9e662c08dde54d14a6bfd0b619f
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    # .NET
    aspnetcore-runtime-8.0 \
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
COPY start.sh bot.mjs flag.txt /home/user/
COPY --from=build /build/out /home/user/out

RUN chmod 755 /home/user/bot.mjs /home/user/start.sh && chmod 644 /home/user/flag.txt
CMD kctf_setup && \
    mount -t tmpfs none /tmp && \
    kctf_drop_privs /home/user/start.sh
