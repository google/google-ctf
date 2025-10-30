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
FROM gcr.io/kctf-docker/challenge@sha256:0f7d757bcda470c3bbc063606335b915e03795d72ba1d8fdb6f0f9ff3757364f

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -yq --no-install-recommends tzdata apache2 \
    && ln -fs /usr/share/zoneinfo/Europe/Berlin /etc/localtime \
    && dpkg-reconfigure --frontend noninteractive tzdata \
    && rm -rf /var/lib/apt/lists/*

RUN service apache2 start

# For CGI sandboxing
RUN ln -s /etc/apache2/mods-available/cgi.load /etc/apache2/mods-enabled/cgi.load
RUN ln -s /etc/apache2/mods-available/actions.load /etc/apache2/mods-enabled/actions.load
COPY cgi-bin /usr/lib/cgi-bin

COPY apache2-kctf-nsjail.conf /etc/apache2/conf-enabled/

RUN mkdir /web && touch /web/circo.circo && chmod a+rx /web/circo.circo

VOLUME /var/log/apache2
VOLUME /var/run/apache2

RUN mkdir /home/user
RUN chown user /home/user
USER user
#COPY flag.txt config.circo /home/user/
RUN echo CTF{TestingFlag} > /home/user/flag.txt
COPY cgi-bin.nsjail.cfg main.final /home/user/
RUN mkdir /home/user/dev /home/user/etc /home/user/tmp /home/user/proc

USER root

CMD kctf_setup \
    && setsid --wait bash -c 'source /etc/apache2/envvars && APACHE_RUN_USER=user APACHE_RUN_GROUP=user /usr/sbin/apache2 -D FOREGROUND' & \
    child_pid=$! trap "kill -SIGINT $child_pid" SIGINT; wait $child_pid
