# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM gcr.io/kctf-docker/challenge@sha256:9f15314c26bd681a043557c9f136e7823414e9e662c08dde54d14a6bfd0b619f

RUN apt-get update && apt-get install -y python3 python3-pip python3-venv

WORKDIR /app/
COPY requirements.txt requirements.txt
RUN python3 -m venv /venv
RUN /venv/bin/python3 -m pip install -r requirements.txt

EXPOSE 3000

COPY . .

CMD kctf_setup && kctf_drop_privs /venv/bin/python3 -m waitress --listen=0.0.0.0:3000 app:app
