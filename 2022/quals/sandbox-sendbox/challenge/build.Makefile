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

.PHONY: all
all: chal init

chal: LDLIBS=-lprotobuf -lcap
chal: LDFLAGS=-pthread
chal: chal.cc chal.pb.h chal.pb.o

chal.pb.o: chal.pb.cc

chal.pb.cc: chal.pb.h

chal.pb.h: chal.proto
	protoc --cpp_out=. chal.proto

init: LDFLAGS=-static
init: init.o
