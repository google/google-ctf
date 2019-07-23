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

FROM ubuntu:12.04

RUN set -e -x; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user

WORKDIR /
ADD launcher/launcher .
ADD flag.txt .

RUN set -e -x; \
    chown -R user:user /home/user; \
    chown -R user:user /launcher; \
    chown user:user /flag.txt; \
    chmod 700 /home/user; \
    chmod 700 /launcher; \
    chmod 400 /flag.txt;

RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
RUN sed -i -e 's/archive/old-releases/g' /etc/apt/sources.list
RUN apt-get update && apt-get install -y openssh-client curl sshpass netcat && rm -rf /var/lib/apt/lists/
CMD ["/launcher"]
