# Copyright 2021 Google LLC
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

# Author: Ian Eldred Pudney
#
FROM ubuntu:20.04 as chroot

RUN /usr/sbin/useradd --no-create-home -u 1000 user

FROM gcr.io/kctf-docker/challenge@sha256:56f7dddff69d08d4d19f4921c724d438cf4d59e434c601f9776fd818368b7107

#COPY --from=chroot / /chroot

RUN apt update && apt install -y zip unzip
RUN pip3 install cryptography

COPY nsjail.cfg /home/user/
COPY cap_drop_args.py /bin/cap_drop_args.py
COPY kctf_drop_privs /bin/kctf_drop_privs

COPY server.sh /home/user/
COPY autorunner.py /home/user/
COPY recv_zip /home/user/
COPY flag /home/user/
COPY flag /
COPY public_key /home/user/
COPY stderr.sh /home/user/stderr.sh
RUN chown -R user:user /home/user
RUN chmod -R ugo-w /home/user
RUN chmod ugo+rx /home/user/*
RUN mkdir /home/user/unzipped
RUN ln -s `which python3` /usr/bin/python
RUN ln -s `which python3` /usr/bin/python38
RUN ln -s `which python3` /usr/bin/python385
COPY turbozipfile.cpython-38-x86_64-linux-gnu.so /home/user/

#CMD socat \
#      TCP-LISTEN:1337,reuseaddr,fork \
#      EXEC:"/bin/bash"

CMD kctf_setup && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg -- /home/user/stderr.sh"
