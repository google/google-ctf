# Copyright 2024 Google LLC
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
FROM ubuntu:24.04 as chroot

RUN /usr/sbin/useradd --no-create-home -u 1001 user

RUN apt-get update && \
    apt-get install -y qemu-system-x86 socat

COPY run_qemu.sh rootfs.img bzImage /home/user/

FROM gcr.io/kctf-docker/challenge@sha256:eb0f8c3b97460335f9820732a42702c2fa368f7d121a671c618b45bbeeadab28

COPY --from=chroot / /chroot

COPY nsjail.cfg /home/user/

CMD kctf_setup && \
    chmod 0777 /dev/kvm && \
    chmod 0777 /dev/vhost-vsock && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg -- /home/user/run_qemu.sh"
