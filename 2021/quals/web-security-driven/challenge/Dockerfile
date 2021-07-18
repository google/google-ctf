# Copyright 2021 Google LLC
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

FROM gcr.io/kctf-docker/challenge@sha256:56f7dddff69d08d4d19f4921c724d438cf4d59e434c601f9776fd818368b7107

RUN apt update && \
    apt install -y curl && \
    curl -sL https://deb.nodesource.com/setup_14.x | bash - && \
    apt install -y nodejs

COPY src/ /home/ctfuser/

WORKDIR /home/ctfuser/

RUN npm ci --only=production
ENV NODE_ENV "production"

RUN npm install

RUN apt install -y netcat

COPY ./start.sh /tmp

CMD kctf_setup && \
    /tmp/start.sh
