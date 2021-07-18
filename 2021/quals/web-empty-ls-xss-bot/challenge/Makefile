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

all: admin_client.crt.pem admin_client.key.pem

admin_client.crt.pem: ../../web-empty-ls/challenge/admin_client.crt.pem
	cp ../../web-empty-ls/challenge/admin_client.crt.pem .
	chmod 644 admin_client.crt.pem

admin_client.key.pem: ../../web-empty-ls/challenge/admin_client.key.pem
	cp ../../web-empty-ls/challenge/admin_client.key.pem .
	chmod 644 admin_client.key.pem
