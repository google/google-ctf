# Copyright 2019 Google LLC
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

all: main.cc convert_to_dfa.cc create_machine_code.cc regex_to_nfa.cc create-stub
	g++ -Wall -O2 main.cc convert_to_dfa.cc create_machine_code.cc run_regex.cc regex_to_nfa.cc -o regex

turn: turn_stub_into_cpp.cc
	g++ -Wall -O2 turn_stub_into_cpp.cc -o turn_stub_into_cpp

stub1: stub1.asm
	nasm -f bin stub1.asm -o stub1.o

stub2: stub2.asm
	nasm -f bin stub2.asm -o stub2.o

stub3: stub3.asm
	nasm -f bin stub3.asm -o stub3.o

stub4: stub4.asm
	nasm -f bin stub4.asm -o stub4.o

create-stub: turn stub1 stub2 stub3 stub4
	./turn_stub_into_cpp

clean:
	rm regex turn_stub_into_cpp stub*.o stubs.h
