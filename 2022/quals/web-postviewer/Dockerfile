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

FROM node:16 as chroot


RUN /usr/sbin/useradd --no-create-home -u 1337 user

COPY src/ /home/user/
COPY start.sh /home/user/

RUN chown -R 1337 /home/user/*
WORKDIR /home/user/
RUN npm ci --only=production
RUN npm install
RUN apt-get update && apt-get install -y netcat

FROM gcr.io/kctf-docker/challenge@sha256:d884e54146b71baf91603d5b73e563eaffc5a42d494b1e32341a5f76363060fb

COPY --from=chroot / /chroot
COPY nsjail.cfg /home/user/
COPY drop_privs /home/user/

CMD kctf_setup && \
    (/home/user/drop_privs nsjail --config /home/user/nsjail.cfg /home/user/start.sh)
