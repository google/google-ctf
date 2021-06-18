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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


void a(int a) {
	puts("Flag: HCL8{Maths_are_hard_comput3rs_are_harder}");
	exit(0);
}

int main(int argc, char **argv) {
	int x = 1, y = 2, input = 0;

	setbuf(stdout, NULL);
	setvbuf(stdout, NULL, _IONBF, 0);
	puts(".: fpeu :.");
	puts("1. dump the binary.");
	puts("2. play the game.");
	puts("3. quit.");

	scanf("%d", &input);

	switch(input){
		case 1: {
							int fd = open("./bin_to_run", O_RDONLY);
							char buf[1024];
							int buflen;
							while((buflen = read(fd, buf, 1024)) > 0) {
								write(1, buf, buflen);
							}
							close(fd);
							return 0;
						}
		case 2:

						printf("> ");
						scanf("%d", &x);
						printf("> ");
						scanf("%d", &y);
						if (x != 0 && y != 0) {
							signal(SIGFPE, a);
							return x / y;
						}
		default:
						return 0;
	}
}
