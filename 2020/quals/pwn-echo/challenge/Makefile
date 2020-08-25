# Copyright 2020 Google LLC
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

all: entry echo_srv launcher

entry: entry.c
	gcc entry.c -O2 -lcap -static -o entry

echo_srv: echo_srv.cc
	g++ -std=c++17 -fstack-protector-strong echo_srv.cc -O2 -o echo_srv

launcher: launcher.c
	gcc launcher.c -static -O2 -o launcher

clean:
	$(RM) entry echo_srv launcher

.PHONY: all clean
