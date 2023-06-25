# Copyright 2023 Google LLC
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

FROM node:18-alpine AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app
COPY src/package.json /app/package.json
RUN npm install --frozen-lockfile

# # Rebuild the source code only when needed
FROM node:18-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY src/ /app/
RUN npm run build

FROM gcr.io/kctf-docker/challenge@sha256:d884e54146b71baf91603d5b73e563eaffc5a42d494b1e32341a5f76363060fb AS chroot

RUN apt update && \
    apt install -y curl git gnupg \
    && wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/googlechrome-linux-keyring.gpg \
    && sh -c 'echo "deb [arch=amd64 signed-by=/usr/share/keyrings/googlechrome-linux-keyring.gpg] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list' \
    && wget -q -O - https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -yq --no-install-recommends \
        ca-certificates \
        fonts-liberation \
        libappindicator3-1 \
        libasound2 \
        libatk-bridge2.0-0 \
        libatk1.0-0 \
        libc6 \
        libcairo2 \
        libcups2 \
        libdbus-1-3 \
        libexpat1 \
        libfontconfig1 \
        libgbm1 \
        libgcc1 \
        libglib2.0-0 \
        libgtk-3-0 \
        libnspr4 \
        libnss3 \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libstdc++6 \
        libx11-6 \
        libx11-xcb1 \
        libxcb1 \
        libxcomposite1 \
        libxcursor1 \
        libxdamage1 \
        libxext6 \
        libxfixes3 \
        libxi6 \
        libxrandr2 \
        libxrender1 \
        libxshmfence1 \
        libxss1 \
        libxtst6 \
        lsb-release \
        xdg-utils \
        # google-chrome-stable \
        fonts-freefont-ttf \
        nodejs \
        python3-pip \
     && rm -rf /var/lib/apt/lists/*

# RUN groupadd -r bloguser && useradd -rm -g bloguser bloguser
# USER bloguser

WORKDIR /home/user

## asciidoc install
RUN pip3 install asciidoc

ENV NODE_ENV "production"

COPY --from=builder   /app/public ./public
COPY --from=builder   /app/package.json ./package.json
COPY --from=builder   /app/.next/standalone ./
COPY --from=builder  /app/.next/static ./.next/static
COPY ./start.sh ./
COPY ./cleanup.sh ./


## Final runner stage
FROM gcr.io/kctf-docker/challenge@sha256:d884e54146b71baf91603d5b73e563eaffc5a42d494b1e32341a5f76363060fb AS runner

COPY --from=chroot / /chroot
WORKDIR /home/user

COPY nsjail.cfg /home/user/
COPY drop_privs /home/user/

CMD kctf_setup && \
    (/home/user/drop_privs nsjail --config /home/user/nsjail.cfg /home/user/start.sh)
