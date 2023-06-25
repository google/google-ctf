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

# Please use docker for building your challenges so that SREs can rebuild it
# if necessary without installing any dependencies.
chal: chal.cc CMakeLists.txt build.dockerfile
	- docker rm tmp-chal-container 2>/dev/null
	docker build -t tmp-chal-image -f build.dockerfile .
	docker run --name tmp-chal-container tmp-chal-image /bin/true
	docker cp tmp-chal-container:/build/chal .
	- docker rm tmp-chal-container 2>/dev/null
	touch chal
