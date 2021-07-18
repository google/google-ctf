# Copyright 2021 Google LLC
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

challenge: first.s main.s gen_hex_funcs.py build.dockerfile build.makefile
	- docker rm tmp-hexagon-container 2>/dev/null
	docker build -t tmp-chal-image -f build.dockerfile .
	docker run --name tmp-hexagon-container tmp-chal-image /bin/true
	docker cp tmp-hexagon-container:/build/challenge challenge
	- docker rm tmp-hexagon-container 2>/dev/null
	touch challenge
