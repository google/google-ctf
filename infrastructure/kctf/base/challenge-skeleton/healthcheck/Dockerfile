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
FROM ubuntu:19.10

RUN apt-get -y update
RUN apt-get -y upgrade

RUN apt-get -y install python2.7 python-pip
RUN pip install pwntools

RUN apt-get -y install cpio

COPY .gen/exploit.cpio.enc /

RUN /usr/sbin/useradd --no-create-home -u 1000 user
COPY files /home/user
RUN mkdir /home/user/.pwntools-cache && echo never > /home/user/.pwntools-cache/update

CMD openssl aes-256-cbc -d -in exploit.cpio.enc -out exploit.cpio -K "$(cat /keys/exploit.key)" -nosalt -iv 00000000000000000000000000000000 && < exploit.cpio cpio -i && rm /exploit.cpio.enc && rm /exploit.cpio && setpriv --init-groups --reuid user --regid user --inh-caps=-all -- /exploit/run.sh & /home/user/healthz.py
