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
#
# This generates a docker image that can be used by the players to locally
# experiment with the challenge

FROM ubuntu:20.04 as build_files

ENV HASH=aa81c10a557f4c591e7c91aaeb2342ced4529f96236ebd2e8e0de277b446d9214370ec924b52a831876904b6e2ff80399a642cb980fc73b68747038d452bae6c

RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get install -y wget

RUN cd /tmp && wget https://storage.googleapis.com/gctf-2021-attachments-project/${HASH} -O build.tar.gz \
    && tar -xf build.tar.gz

# Copy over the release artifacts to a clean VM
FROM ubuntu:21.04 as chroot

# Install deps
RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -y \
        libjson-c5 libfdt1 libglib2.0-0 libpixman-1-0 socat qemu-utils \
 && rm -rf /var/lib/apt/lists/*

# Copy qemu + bios
COPY --from=build_files /tmp/build/qemu-system-x86_64 /app/qemu-system-x86_64
COPY --from=build_files /tmp/build/pc-bios/ /app/pc-bios

# Copy emulator + library
COPY --from=build_files /tmp/build/emulator /app/emulator
COPY --from=build_files /tmp/build/libvfio-user.so /app/
COPY --from=build_files /tmp/build/libvfio-user.so.0 /app/
COPY --from=build_files /tmp/build/libvfio-user.so.0.0.1 /app/

# Copy images

COPY --from=build_files /tmp/guest-image/out/flag_vm.qcow2 /app/flag_vm.qcow2
COPY --from=build_files /tmp/guest-image/out/challenge_vm.qcow2 /app/challenge_vm.qcow2
COPY --from=build_files /tmp/guest-image/out/vmlinuz /app/
COPY --from=build_files /tmp/guest-image/out/initrd.img /app/

# Copy launcher
COPY launcher.sh /app/

FROM gcr.io/kctf-docker/challenge@sha256:56f7dddff69d08d4d19f4921c724d438cf4d59e434c601f9776fd818368b7107

COPY --from=chroot / /chroot

COPY nsjail.cfg /home/user/

CMD kctf_setup && \
    chmod 777 /dev/kvm && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg -- /app/launcher.sh"
