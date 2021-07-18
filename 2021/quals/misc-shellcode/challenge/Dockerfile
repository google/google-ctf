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

# Build a chroot for the python orchestrator.
FROM ubuntu:20.04 as chroot
RUN apt-get update && apt-get install -y qemu qemu-user qemu-user-static gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu libc6-arm64-cross python3
RUN apt-get install -y gdb gdb-multiarch
RUN ln -s /usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1 /lib/ld-linux-aarch64.so.1

RUN /usr/sbin/useradd -u 1000 user
COPY flag /home/user/flag
COPY runner.py /home/user/runner.py
COPY chal-aarch64 /home/user/chal-aarch64
COPY chal-x86-64 /home/user/chal-x86-64
RUN chmod a+rw /home/user/*

FROM gcr.io/kctf-docker/challenge@sha256:56f7dddff69d08d4d19f4921c724d438cf4d59e434c601f9776fd818368b7107

COPY --from=chroot / /chroot

COPY nsjail.cfg /home/user/

CMD kctf_setup && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg -- /usr/bin/python3 /home/user/runner.py"
