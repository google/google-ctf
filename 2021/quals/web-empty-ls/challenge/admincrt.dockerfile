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

# The entire purpose of this file is to allow Makefile
# to generate admin_client.crt.pem and admin_client.key.pem .

FROM ubuntu:20.04 as build

RUN apt-get update && apt-get install -y wget
RUN wget -q https://golang.org/dl/go1.16.5.linux-amd64.tar.gz
RUN rm -rf /usr/local/go && tar -C /usr/local -xzf go1.16.5.linux-amd64.tar.gz
ENV PATH="$PATH:/usr/local/go/bin"

COPY go.mod go.sum clientcrtgentool.go /home/user/
COPY clientcrtgen /home/user/clientcrtgen
RUN cd /home/user && go build clientcrtgentool.go
COPY clientca.crt.pem clientca.key.pem /home/user/

RUN /home/user/clientcrtgentool \
    --user="admin" \
    --output=/home/user/admin_client.p12

CMD sleep 1
