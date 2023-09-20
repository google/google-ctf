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
FROM ubuntu:20.04 as chroot

RUN /usr/sbin/useradd -u 1000 user

RUN apt-get update \
    && apt-get install -yq --no-install-recommends \
       curl ca-certificates socat gnupg lsb-release software-properties-common php-cgi \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSL https://deb.nodesource.com/gpgkey/nodesource.gpg.key | apt-key add - \
    && (echo "deb https://deb.nodesource.com/node_10.x $(lsb_release -s -c) main";\
        echo "deb-src https://deb.nodesource.com/node_10.x $(lsb_release -s -c) main") \
       > /etc/apt/sources.list.d/nodesource.list \
    && add-apt-repository universe \
    && apt-get update \
    && apt-get install -yq --no-install-recommends nodejs socat \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /mnt/disks/sessions
RUN mkdir -p /mnt/disks/uploads

VOLUME /mnt/disks/sessions
VOLUME /mnt/disks/uploads

COPY web-apps /web-apps
COPY web-servers /web-servers

COPY flag /

FROM gcr.io/kctf-docker/challenge@sha256:0f7d757bcda470c3bbc063606335b915e03795d72ba1d8fdb6f0f9ff3757364f

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -yq --no-install-recommends tzdata apache2 \
    && ln -fs /usr/share/zoneinfo/Europe/Berlin /etc/localtime \
    && dpkg-reconfigure --frontend noninteractive tzdata \
    && rm -rf /var/lib/apt/lists/*

RUN service apache2 start

COPY --from=chroot / /chroot

# For Proxy
RUN ln -s /etc/apache2/mods-available/proxy.load /etc/apache2/mods-enabled/
RUN ln -s /etc/apache2/mods-available/proxy_http.load /etc/apache2/mods-enabled/

# For CGI sandboxing
RUN ln -s /etc/apache2/mods-available/cgi.load /etc/apache2/mods-enabled/cgi.load
RUN ln -s /etc/apache2/mods-available/actions.load /etc/apache2/mods-enabled/actions.load
RUN ln -s /chroot/web-apps /web-apps
COPY cgi-bin /usr/lib/cgi-bin

COPY apache2-kctf-nsjail.conf /etc/apache2/conf-enabled/

COPY web-servers.nsjail.cfg /home/user/web-servers.nsjail.cfg
COPY cgi-bin.nsjail.cfg /home/user/cgi-bin.nsjail.cfg

VOLUME /var/log/apache2
VOLUME /var/run/apache2

CMD kctf_setup \
    && (kctf_drop_privs nsjail --config /home/user/web-servers.nsjail.cfg --port 8081 -- /web-servers/nodejs.sh &) \
    && bash -c 'source /etc/apache2/envvars && APACHE_RUN_USER=user APACHE_RUN_GROUP=user /usr/sbin/apache2 -D FOREGROUND'
