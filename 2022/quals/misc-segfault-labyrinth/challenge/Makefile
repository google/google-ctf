# Copyright 2022 Google LLC
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

all: challenge challenge-debug

clean:
	rm challenge challenge-debug prologue.o prologue2.o prologue

docker: challenge
	docker build -t segfaultlabyrinth .

prologue.o: prologue.S
	nasm -felf64 -o prologue.o prologue.S

prologue2.o: prologue.o
	objcopy -O binary prologue.o prologue
	objcopy -I binary -O elf64-x86-64 prologue prologue2.o

challenge-debug: challenge.c prologue2.o
	gcc -g -o challenge-debug -Wall -DDEBUG prologue2.o challenge.c 

challenge: challenge.c prologue2.o
	gcc -O3 -o challenge -Wall prologue2.o challenge.c
	strip challenge

.PHONY: all clean docker
