# Copyright 2020 Google LLC
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

all: clean build deploy

clean:
	- docker rm misc-ml-steal-{build,deploy} 2>/dev/null
	- docker rmi -f misc-ml-steal-{build,deploy} 2>/dev/null
	- rm -rf mlsteal.cpython-38-x86_64-linux-gnu.so

build: build_model.py Dockerfile.build
	docker build -t misc-ml-steal-build -f Dockerfile.build .
	docker run --name misc-ml-steal-build misc-ml-steal-build /bin/true
	docker cp misc-ml-steal-build:/build/mlsteal.cpython-38-x86_64-linux-gnu.so mlsteal.cpython-38-x86_64-linux-gnu.so
	- docker rm misc-ml-steal-build 2>/dev/null
	- docker rmi -f misc-ml-steal-build 2>/dev/null

deploy: query.py weights.gz mlsteal.cpython-38-x86_64-linux-gnu.so Dockerfile.deploy
	docker build -t misc-ml-steal-deploy -f Dockerfile.deploy .
	docker create --name misc-ml-steal-deploy -i -t misc-ml-steal-deploy
	docker export misc-ml-steal-deploy | xz > ../attachments/ml-steal.tar.xz
	rm -rf mlsteal.cpython-38-x86_64-linux-gnu.so
	- docker rm misc-ml-steal-deploy 2>/dev/null
	- docker rmi -f misc-ml-steal-deploy 2>/dev/null

