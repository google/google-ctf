// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

class RetEx{};
int r0, r1, r2, r3, r4, r5, r6, r7;

int memory[2048];
int* sptr = memory + 2048;
#define push(x) *--sptr = (x)
#define pop(x) x = *sptr++

REPLACE_ME

int main() {
	setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
    setvbuf(stderr,NULL,_IONBF,0);

	try {
		start();
	}
	catch (const RetEx&) {}
}
