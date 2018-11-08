#!/bin/bash

# Copyright 2018 Google LLC

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

# Author: Ian Eldred Pudney

FROM ubuntu:16.04
RUN set -e -x; \
        apt-get -y update; \
        apt-get -y upgrade; \
	apt-get install -y python2.7
RUN set -e -x; \
        groupadd -g 1337 user; \
        useradd -g 1337 -u 1337 -m user

COPY validator/hash_asparagus.py /home/user/hash_asparagus.py
COPY validator/validator.py /home/user/validator.py
COPY validator/validator_driver.py /home/user/validator_driver.py
COPY validator/expected /home/user/expected
COPY validator/infile /home/user/infile

RUN set -e -x; \
        chown -R root:root /home/user; \
        chmod 0555 /home/user/*;

USER user
CMD cd /home/user && /usr/bin/python2.7 -u validator_driver.py
