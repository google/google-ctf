#!/bin/bash -eu
#
# Copyright 2018 Google LLC
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

openssl genrsa -out key_priv.pem 1024
openssl rsa -in key_priv.pem -inform pem -pubout -out healthcheck/key_pub.pem -outform pem
printf ".oO %s Oo." `grep -oP --color=never '(CTF\{.*\})' metadata.json` | \
  openssl rsautl -out healthcheck/flag.txt -encrypt -pkcs -pubin -inkey healthcheck/key_pub.pem -keyform pem
openssl rsautl -in healthcheck/flag.txt -decrypt -pkcs -inkey key_priv.pem -keyform pem
echo
