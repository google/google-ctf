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
FROM ubuntu:18.04
RUN set -e -x; \
        apt-get -y update; \
        apt-get -y upgrade
RUN set -e -x; \
        apt-get -y update; apt-get -y install default-jdk g++ make locales wget \
        && sed 's/# en_US.UTF-8/en_US.UTF-8/' -i /etc/locale.gen \
        && locale-gen
RUN set -e -x; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user
ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8
COPY src/ home/user/
RUN set -e -x ;\
    chown -R user:user /home/user
WORKDIR /home/user
RUN make
USER user
ENV PROJECT_ROOT /home/user
CMD cd /home/user && make --quiet run
