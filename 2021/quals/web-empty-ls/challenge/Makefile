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

# The entire purpose of this file is to regen the admin's client cert and key.
# Don't run this makefile, because there's typically no reason to regen the
# admin's client cert.

all: admin_client.crt.pem admin_client.key.pem

# https://stackoverflow.com/questions/15144046/converting-pkcs12-certificate-into-pem-using-openssl
admin_client.crt.pem: admin_client.p12
	openssl pkcs12 -in admin_client.p12 -out admin_client.crt.pem -clcerts -nokeys -passin pass:changeit
	chmod 644 admin_client.crt.pem

admin_client.key.pem: admin_client.p12
	openssl pkcs12 -in admin_client.p12 -out admin_client.key.pem -nocerts -nodes -passin pass:changeit
	chmod 644 admin_client.key.pem

admin_client.p12: clientcrtgentool.go clientcrtgen/clientcrtgen.go admincrt.dockerfile
	- docker rm tmp-empty-ls-admin-crt-container 2>/dev/null
	docker build -t tmp-empty-ls-admin-crt-image -f admincrt.dockerfile .
	docker run --name tmp-empty-ls-admin-crt-container tmp-empty-ls-admin-crt-image /bin/true
	docker cp tmp-empty-ls-admin-crt-container:/home/user/admin_client.p12 .
	- docker rm tmp-empty-ls-admin-crt-container 2>/dev/null
	touch admin_client.p12
	chmod 644 admin_client.p12
