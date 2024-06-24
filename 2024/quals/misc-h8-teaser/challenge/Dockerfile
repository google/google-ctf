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
FROM ubuntu:22.04 as chroot

RUN /usr/sbin/useradd --no-create-home -u 1000 user

RUN apt-get update \
    && apt-get install -yq --no-install-recommends python3 python3-pip libjpeg-dev zlib1g-dev socat libglu1-mesa-dev freeglut3-dev mesa-common-dev libfreetype-dev libfreetype6 \
    && rm -rf /var/lib/apt/lists/*

COPY hackceler8-2023 /home/user/hackceler8-2023

WORKDIR /home/user/hackceler8-2023/game
RUN python3 --version
RUN pip3 install -r requirements.txt
RUN pip3 install gmpy2

FROM gcr.io/kctf-docker/challenge@sha256:0f7d757bcda470c3bbc063606335b915e03795d72ba1d8fdb6f0f9ff3757364f

COPY --from=chroot / /chroot

COPY nsjail.cfg /home/user/

CMD kctf_setup && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg -- /usr/bin/python3 -u /home/user/hackceler8-2023/game/server.py"
