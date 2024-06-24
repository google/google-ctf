# Copyright 2020 Google LLC
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
FROM gcr.io/kctf-docker/challenge@sha256:d884e54146b71baf91603d5b73e563eaffc5a42d494b1e32341a5f76363060fb

RUN apt-get update && apt-get install -y gnupg2 wget

RUN install -d -m 0755 /etc/apt/keyrings \
  && wget -q https://packages.mozilla.org/apt/repo-signing-key.gpg -O- | tee /etc/apt/keyrings/packages.mozilla.org.asc > /dev/null \
    && echo "deb [signed-by=/etc/apt/keyrings/packages.mozilla.org.asc] https://packages.mozilla.org/apt mozilla main" | tee -a /etc/apt/sources.list.d/mozilla.list > /dev/null \
    # && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install firefox -y \
    && wget -q -O - https://deb.nodesource.com/setup_20.x | bash - \
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
        wget \
        xdg-utils \
        nodejs \
        fonts-ipafont-gothic fonts-wqy-zenhei fonts-thai-tlwg fonts-khmeros fonts-kacst fonts-freefont-ttf \
  && rm -rf /var/lib/apt/lists/*


RUN mkdir /home/user
COPY bot.js package.json package-lock.json /home/user/
RUN cd /home/user && npm install && npx puppeteer browsers install firefox@stable
RUN cp -r /root/.cache /home/user/


CMD kctf_setup && \
    mount -t tmpfs none /tmp && \
    mkdir /tmp/mozilla-userdata && chmod o+rwx /tmp/mozilla-userdata && \
    while true; do \
      FLAG="${FLAG}" PAGE_URL="${PAGE_URL}" BOT_TIMEOUT="${BOT_TIMEOUT}" /usr/bin/node /home/user/bot.js; \
    done & \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow socat STDIN TCP\:localhost\:1338"
