# Copyright 2019 Google LLC
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

from archlinux/base

RUN pacman -Syy
RUN pacman -Sy --noconfirm python2
RUN pacman -Sy --noconfirm socat
RUN pacman -Sy --noconfirm qemu qemu-arch-extra gnu-netcat

RUN set -e -x; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user

add polyglot.py /

RUN set -e -x ; chmod 0555 /polyglot.py

CMD socat tcp-l:1337,fork exec:'python2 -u polyglot.py'
