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

FROM ubuntu:20.04

RUN set -e -x; \
        groupadd -g 1338 user; \
        useradd -g 1338 -u 1338 -m user

COPY challenge/launcher /home/user/
COPY challenge/echo_srv.cc /root/
COPY challenge/echo_srv /root/
COPY challenge/entry /root/
COPY flag /root/

RUN set -e -x; \
    chown -R user:user /root; \
    chown -R 1339:1339 /home/user; \
    chmod 700 /root

USER user
CMD cd /root && ./entry
