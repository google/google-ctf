# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM haproxytech/haproxy-debian:2.4

RUN apt-get update \
    && apt-get install -yq --no-install-recommends \
       git ca-certificates lsb-release software-properties-common \
       unzip build-essential libssl-dev lua5.3 liblua5.3-dev tcpdump \
       python3-pycryptodome python3-requests

COPY haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg
COPY start.sh /

RUN mkdir /tmp/haproxy
WORKDIR /tmp/haproxy

COPY oauth_pubkey.pem .
COPY eth.lua .
COPY reload.sh .
COPY force-reload.sh .
COPY update_pubkey.py .
RUN ln -s socket/nginx.socket /var/lib/haproxy/nginx.socket

RUN git clone https://github.com/haproxytech/haproxy-lua-http.git
RUN cp haproxy-lua-http/http.lua .
RUN git clone https://github.com/haproxytech/haproxy-lua-oauth.git
RUN chmod +x haproxy-lua-oauth/install.sh
RUN cd haproxy-lua-oauth && ./install.sh luaoauth
RUN rm -r haproxy-lua-http haproxy-lua-oauth

RUN rm -rf /var/lib/apt/lists/*

#COPY http.lua .

VOLUME /tmp
VOLUME /var/log
VOLUME /var/lib/haproxy/
VOLUME /var/run

CMD bash /start.sh
