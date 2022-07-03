# Copyright 2022 Google LLC
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

FROM ubuntu:20.04 as chroot

RUN /usr/sbin/useradd --no-create-home -u 1000 user

# install maven
RUN apt-get update && \
    apt-get -y --no-install-recommends install maven python3-pip

# copy server code
COPY server /home/user
COPY start.sh /home/user
RUN chmod 755 /home/user/templates

RUN pip install -r /home/user/requirements.txt

# copy and create jar of chatbot
COPY chatbot /home/user/chatbot
WORKDIR /home/user/chatbot
RUN mvn clean package shade:shade

FROM gcr.io/kctf-docker/challenge@sha256:d884e54146b71baf91603d5b73e563eaffc5a42d494b1e32341a5f76363060fb

COPY --from=chroot / /chroot

COPY nsjail.cfg /home/user/

CMD kctf_setup && \
    (kctf_drop_privs nsjail --config /home/user/nsjail.cfg -- /bin/bash start.sh)
