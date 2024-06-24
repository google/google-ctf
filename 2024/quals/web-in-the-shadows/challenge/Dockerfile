# Copyright 2024 Google LLC
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

FROM node@sha256:162d92c5f1467ad877bf6d8a098d9b04d7303879017a2f3644bfb1de1fc88ff0 AS tailwind
WORKDIR /tailwind/
RUN npm install -g tailwindcss@3.4.3
COPY tailwind.config.js input.css views/*.html /tailwind/
RUN npx tailwindcss -i input.css -o style.css --minify

FROM golang@sha256:3b55bf3986b2651a515f48ddf758b80a7d78d8be18706fd98aa74241992dac96 AS build
WORKDIR /golang/
COPY server.go server_test.go go.mod go.work admin_cookie_value.txt flag.txt hmac_key.txt /golang/
COPY js/ /golang/js
COPY views/ /golang/views
COPY --from=tailwind /tailwind/style.css /golang/
RUN go test && mkdir /golang/bin/ && go build -v -o /golang/bin/server server.go 

# debian:12.5-slim
FROM debian@sha256:804194b909ef23fb995d9412c9378fb3505fe2427b70f3cc425339e48a828fca AS chroot
RUN  apt update && \
     apt install -y ca-certificates && \
     rm -rf /var/lib/apt/lists/*

FROM gcr.io/kctf-docker/challenge@sha256:d884e54146b71baf91603d5b73e563eaffc5a42d494b1e32341a5f76363060fb
WORKDIR /home/app/
COPY --from=chroot / /chroot
COPY --from=build /golang/bin/server /chroot/server
COPY ./nsjail.cfg /nsjail.cfg
COPY ./nsjail_entrypoint.sh /chroot/nsjail_entrypoint.sh
COPY ./run.sh /run.sh

CMD /run.sh