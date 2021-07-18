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

all: zone443.dev.fullchain.crt.pem zone443.dev.key.pem clientca.crt.pem

zone443.dev.fullchain.crt.pem: ../../web-empty-ls/challenge/zone443.dev.fullchain.crt.pem
	cp ../../web-empty-ls/challenge/zone443.dev.fullchain.crt.pem .
	chmod 644 zone443.dev.fullchain.crt.pem

zone443.dev.key.pem: ../../web-empty-ls/challenge/zone443.dev.key.pem
	cp ../../web-empty-ls/challenge/zone443.dev.key.pem .
	chmod 644 zone443.dev.key.pem

clientca.crt.pem: ../../web-empty-ls/challenge/clientca.crt.pem
	cp ../../web-empty-ls/challenge/clientca.crt.pem .
	chmod 644 clientca.crt.pem
