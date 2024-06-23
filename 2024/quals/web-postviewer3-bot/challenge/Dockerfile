# Copyright 2024 Google LLC
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
FROM gcr.io/kctf-docker/challenge@sha256:eb0f8c3b97460335f9820732a42702c2fa368f7d121a671c618b45bbeeadab28

RUN apt-get update && apt-get install -y gnupg2 wget

RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list' \
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
        nodejs \
    && rm -rf /var/lib/apt/lists/*

VOLUME /mnt/disks/logs/


COPY bot.js package.json package-lock.json visit.js /home/user/
RUN cd /home/user && npm install
RUN cp -r /root/.cache /home/user/

RUN apt-get update \
    && apt-get install -yq --no-install-recommends xvfb \
    && rm -rf /var/lib/apt/lists/*;

CMD kctf_setup && \
    mount -t tmpfs none /tmp && \
    mkdir /tmp/chrome-userdata && chmod o+rwx /tmp/chrome-userdata && \
    while true; do \
      kctf_drop_privs env BOT_TIMEOUT="${BOT_TIMEOUT}" MAX_BROWSERS="${MAX_BROWSERS}" FLAG="${FLAG}" PAGE_URL="${PAGE_URL}" xvfb-run /usr/bin/node /home/user/bot.js; \
      killall chrome; \
    done & \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow socat STDIN TCP\:localhost\:1338"
