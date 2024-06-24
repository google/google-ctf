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
build:
	mkdir -p build
	cmake -S src -B build -D CMAKE_C_COMPILER=clang -D CMAKE_CXX_COMPILER=clang++
	cmake --build build

test: build
	./build/rns_test

testchall: build
	echo "fcedd5ab42f188b49760fca0f99affc9" | ./build/challenge

testeasteregg: build
	./build/challenge a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a

clean:
	rm -rf build

.PHONY: build test testchall testeasteregg clean
