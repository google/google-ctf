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
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


extern long _r_debug;

const size_t
flag[]={0xfffca8b6,0xfffca8b1,0xfffca8ba,0xfffca8a6,0xfffca8e9,0xfffca8b7,0xfffca8cd,0xfffca8d6,0xfffca89e,0xfffca8de,0xfffca8d3,0xfffca8cd,0xfffca8e7,0xfffca8dd,0xfffca8e3,0xfffca8cd,0xfffca8d2,0xfffca8d7,0xfffca8d2,0xfffca8dc,0xfffca8e2,0xfffca8cd,0xfffca8d2,0xfffca8dd,0xfffca8cd,0xfffca8d7,0xfffca8e2,0xfffca8cd,0xfffca8e1,0xfffca8e2,0xfffca8cf,0xfffca8e2,0xfffca8d7,0xfffca8d1,0xfffca8cf,0xfffca8da,0xfffca8da,0xfffca8e7,0xfffca8eb,0x505becba,0x2dfcecaf,0x616ce48e,0x616ce48e,0x616ce48e,0x2074cd6e,0x70c93,0xfffca86e,0};

__attribute__((constructor))
void f3(int volatile salt){
	  static unsigned char bss;
    unsigned char *probe = malloc(0x10);

    if (probe - &bss > 0x20000) {
			salt += 4;
			return;
		} else {
			asm("pop rbx");
			asm("pop rdx");
			asm("pop rcx");
			asm("push rax");
			asm("ret");
		}
}

__attribute__((constructor))
void my_function(int arg1) {
	if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1)  {
		asm("jmp rax");
		asm("ret");
	}
}
__attribute__((constructor))
void f2(int arg1) {
    if(getenv("LD_PRELOAD")) {
			asm("pop rbx");
			asm("pop rax");
			asm("pop rcx");
			asm("ret");
		} else {
			if(arg1) {
				f3(arg1);
			}
		}
}


int main(int argc, char** argv) {
	if (argc != 4) {
		puts("./bin <part1> <part2> <part3>");
		return 0;
	}
	__float128 saltf = 123.0;
	__int128 salt = 0;
	_Complex double saltd = 45;
	for(size_t i = 0; i < 1337; i++){
		if (6 % 12 == 6) {
			saltf *= (i/13.0 + 2);
			f2(salt);
			salt += 36;
			saltd = (saltd + 128 % salt);
			f3(salt);
			continue;
		} else {
			puts("nope.");
			return 0;
		}
	}

	if(atoi(argv[1]) == salt) {
		if(atoi(argv[2]) == (int)saltf) {
			if(atoi(argv[3]) == (int)saltd) {
				for(int i=0; flag[i] != 0; i++) {
					printf("%c", (flag[i] + (size_t)salt - (size_t)saltf + (size_t)saltd));
				}
				printf("\n");
				return 0;
			}
		}
	}
	puts("nope.");
	return 0;
}
