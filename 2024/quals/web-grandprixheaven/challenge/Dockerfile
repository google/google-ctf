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
FROM gcr.io/kctf-docker/challenge@sha256:0f7d757bcda470c3bbc063606335b915e03795d72ba1d8fdb6f0f9ff3757364f

COPY heaven_server /home/user/heaven_server
COPY template_server /home/user/template_server

    
RUN apt update && \
    apt install -y curl && \
    curl -sL https://deb.nodesource.com/setup_20.x | bash - && \
    apt install -y nodejs \
    && rm -rf /var/lib/apt/lists/*    
    
WORKDIR /home/user/heaven_server
RUN npm install

COPY ./start.sh /tmp


CMD kctf_setup \
    && /tmp/start.sh


