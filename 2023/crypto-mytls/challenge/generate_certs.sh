#!/bin/bash

# Copyright 2023 Google LLC
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


set -x
set -e

# Generate CA keys
openssl req -new -x509 -days 9999 -keyout ca-key.pem -out ca-crt.pem -subj "/C=/ST=/L=/O=MyTLS/OU=IT/CN=root.mytls" -passout pass:"ctfchall"

# Generate Server cert
openssl ecparam -out server-ecparam.pem -name prime256v1
openssl genpkey -paramfile server-ecparam.pem -out server-ecdhkey.pem
openssl pkey -in server-ecdhkey.pem -pubout -out server-ecdhpubkey.pem
openssl genrsa -out server-rsakey.pem 1024
openssl req -new -key server-rsakey.pem -out server-rsa.csr -subj "/C=/ST=/L=/O=MyTLS/OU=IT/CN=flagserver.mytls"
openssl x509 -req -in server-rsa.csr -CAkey ca-key.pem -CA ca-crt.pem -force_pubkey server-ecdhpubkey.pem -out server-ecdhcert.pem -CAcreateserial -passin pass:"ctfchall" -days 9999

# Generate guest cert
openssl ecparam -out guest-ecparam.pem -name prime256v1
openssl genpkey -paramfile guest-ecparam.pem -out guest-ecdhkey.pem
openssl pkey -in guest-ecdhkey.pem -pubout -out guest-ecdhpubkey.pem
openssl genrsa -out guest-rsakey.pem 1024
openssl req -new -key guest-rsakey.pem -out guest-rsa.csr -subj "/C=/ST=/L=/O=MyTLS/OU=IT/CN=guest.mytls"
openssl x509 -req -in guest-rsa.csr -CAkey ca-key.pem -CA ca-crt.pem -force_pubkey guest-ecdhpubkey.pem -out guest-ecdhcert.pem -CAcreateserial -passin pass:"ctfchall" -days 9999

# Generate admin cert
openssl ecparam -out admin-ecparam.pem -name prime256v1
openssl genpkey -paramfile admin-ecparam.pem -out admin-ecdhkey.pem
openssl pkey -in admin-ecdhkey.pem -pubout -out admin-ecdhpubkey.pem
openssl genrsa -out admin-rsakey.pem 1024
openssl req -new -key admin-rsakey.pem -out admin-rsa.csr -subj "/C=/ST=/L=/O=MyTLS/OU=IT/CN=admin.mytls"
openssl x509 -req -in admin-rsa.csr -CAkey ca-key.pem -CA ca-crt.pem -force_pubkey admin-ecdhpubkey.pem -out admin-ecdhcert.pem -CAcreateserial -passin pass:"ctfchall" -days 9999
