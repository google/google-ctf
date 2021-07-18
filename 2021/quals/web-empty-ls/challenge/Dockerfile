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

# Author: Kegan Thorrez

FROM gcr.io/kctf-docker/challenge@sha256:56f7dddff69d08d4d19f4921c724d438cf4d59e434c601f9776fd818368b7107

RUN wget -q https://golang.org/dl/go1.16.5.linux-amd64.tar.gz
RUN rm -rf /usr/local/go && tar -C /usr/local -xzf go1.16.5.linux-amd64.tar.gz
ENV PATH="${PATH}:/usr/local/go/bin"

COPY go.mod go.sum central.go /home/user/
COPY captcha /home/user/captcha
COPY clientcrtgen /home/user/clientcrtgen
COPY contacthandler /home/user/contacthandler
COPY sitehandler /home/user/sitehandler
COPY userhandler /home/user/userhandler
RUN cd /home/user && go build central.go

COPY zone443.dev.fullchain.crt.pem \
     zone443.dev.key.pem \
     clientca.crt.pem \
     clientca.key.pem \
     bad_words.b64.txt \
     /home/user/
COPY static /home/user/static

CMD kctf_setup \
    && mount -t tmpfs none /tmp \
    && (socat TCP-LISTEN:443,fork TCP:127.0.0.1:8443 &) \
    && kctf_drop_privs /home/user/central
