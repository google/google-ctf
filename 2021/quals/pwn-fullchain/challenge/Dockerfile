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

FROM ubuntu:20.04 as attachments

ENV HASH=c12856fc6c010d643763e678265f7921b7a44dcd7bcb5ced32634d21dfdff0c5f9542d6a5bdcc6639d8834ab1ff25b263affd8952b11e972c2066aa3cae71540

RUN apt update && apt install -yq wget unzip
RUN cd /tmp && wget "https://storage.googleapis.com/gctf-2021-attachments-project/$HASH"
RUN cd /tmp && unzip ${HASH} rootfs.img

FROM ubuntu:20.04 as chroot

ENV DEBIAN_FRONTEND=noninteractive

RUN /usr/sbin/useradd --no-create-home -u 1000 user
RUN apt update && apt install -yq qemu-system-x86 python3

COPY --from=attachments /tmp/rootfs.img /home/user/

COPY bzImage run_qemu.py flag /home/user/
RUN chmod 755 /home/user/run_qemu.py && chmod 644 /home/user/rootfs.img

FROM gcr.io/kctf-docker/challenge@sha256:56f7dddff69d08d4d19f4921c724d438cf4d59e434c601f9776fd818368b7107

COPY --from=chroot / /chroot

COPY nsjail.cfg /home/user/
RUN chmod 644 /home/user/nsjail.cfg

CMD kctf_setup && \
    chmod 0777 /dev/kvm && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg -- /home/user/run_qemu.py"
