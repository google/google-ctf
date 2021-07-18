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

RUN /usr/sbin/useradd --no-create-home -u 1000 user

RUN ln -s `which python3` /usr/bin/python

RUN set -ex; apt-get update -y; apt-get upgrade -y; apt-get install -y rustc=1.47.0+dfsg1+llvm-1ubuntu1~20.04.1; apt-get install -y python3; apt-get install -y build-essential; apt-get install -y cargo; apt-get install -y curl

RUN set -ex; apt-get install -y strace

COPY chal.py /home/user/chal.py
COPY stderr.sh /home/user/stderr.sh
COPY sources/ /home/user/sources
RUN cd /home/user/sources && cargo vendor
RUN mkdir -p /home/user/build-cache; cd /home/user/sources; CARGO_TARGET_DIR=/home/user/build-cache cargo build --frozen --offline

RUN curl -o /home/user/rustup-init https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init
RUN chmod 655 /home/user/rustup-init
RUN mkdir /home/user/rustup
RUN RUSTUP_HOME=/home/user/rustup RUSTUP_INIT_SKIP_PATH_CHECK=yes /home/user/rustup-init --profile minimal --default-toolchain nightly-2020-10-08 -y

RUN chmod 655 /home/user/chal.py /home/user/stderr.sh && \
  find /home/user/sources -type d -exec chmod 755 {} \; && \
  find /home/user/sources -type f -exec chmod 644 {} \; && \
  find /home/user/build-cache -type d -exec chmod 755 {} \; && \
  find /home/user/build-cache -type f -exec chmod 644 {} \;

FROM gcr.io/kctf-docker/challenge@sha256:56f7dddff69d08d4d19f4921c724d438cf4d59e434c601f9776fd818368b7107
COPY --from=chroot / /chroot
COPY nsjail.cfg /home/user/

RUN mknod -m 0666 /chroot/dev/null c 1 3

CMD kctf_setup && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg -- /home/user/stderr.sh"
