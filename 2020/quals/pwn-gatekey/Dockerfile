# Copyright 2020 Google LLC
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

FROM debian:buster-slim
RUN apt-get update && apt-get dist-upgrade && apt -y install qemu-system-x86 && rm -rf /var/lib/apt/lists/*

RUN set -e -x; \
    groupadd -g 1337 user; \
    useradd -g 1337 -u 1337 -m user

COPY initramfs.SECRET.cpio.gz /initramfs.SECRET.cpio.gz
COPY bzImage /bzImage
COPY launch_qemu.sh /launch_qemu.sh

RUN set -e -x; \
    chmod 555 /launch_qemu.sh; \
    chmod 444 /bzImage /initramfs.SECRET.cpio.gz;

CMD /launch_qemu.sh
