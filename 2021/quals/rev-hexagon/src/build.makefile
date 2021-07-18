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

CC=hexagon-unknown-linux-musl-clang
CFLAGS=-Wall -g
LDFLAGS=-static -nostdlib -e start
ASM=-S

%.o : %.s
	$(CC) -c $(CFLAGS) $< -o $@

challenge: first.o main.o hex_funcs.o
	$(CC) $^ -o $@ $(LDFLAGS)

hex_funcs.s: gen_hex_funcs.py
	python3 gen_hex_funcs.py $@
