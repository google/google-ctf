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
#include <unistd.h>

static int late() __attribute__((destructor(101)));
static int late() {
	char flag[] = {'N', 'E', 'J', '>', '}', 'U', 'i', 'Y', 'q', 'g', 'u', 'Y', 'o', 'r', 'Y', 'q', 'i', 't', 'r', 'n', 'Y', 'r', 'n', 'c', 'Y', 'q', 'g', 'o', 'r', '9', '{', '\0'};
	volatile size_t a = 0;
	for (size_t volatile i=1; i; i++) {
			a += 1;
	}
	for(size_t k=0; flag[k]; k++)
		putchar(flag[k]^6);
}


int main(int argc, char** argv) {
	setvbuf(stdout, NULL, _IONBF, 0); 
	volatile size_t a = 0;
	printf("Hello … ");
	sleep(1);
	puts("friend.");
	sleep(10);
	printf("I … ");
	sleep(10);
	a += 3;
	printf("have … ");
	sleep(10);
	printf("a … ");
	sleep(10);
	printf("flag … ");
	sleep(10);
	printf("for … ");
	sleep(10);
	printf("you.\n");
	sleep(10);
	printf("Just … ");
	sleep(10);
	printf("give … ");
	a -= 2;
	sleep(10);
	printf("me … ");
	sleep(10);
	printf("a … ");
	sleep(10);
	printf("moment. ");
	sleep(10);
	printf("It … ");
	sleep(10);
	printf("shouldn't … ");
	sleep(10);
	printf("take … ");
	sleep(10);
	printf("long.\n");
	sleep(10);
	a *= 10;
	printf("I … ");
	sleep(10);
	printf("just … ");
	sleep(10);
	printf("need … ");
	sleep(10);
	printf("to … ");
	sleep(10);
	printf("remember … ");
	sleep(10);
	printf("where … ");
	sleep(10);
	printf("I … ");
	sleep(10);
	a -= 7;
	printf("put … ");
	sleep(10);
	printf("it. \n");
	sleep(10);
	printf("By … ");
	sleep(10);
	printf("the … ");
	sleep(10);
	printf("way … ");
	sleep(10);
	printf("have … ");
	sleep(10);
	printf("you … ");
	sleep(10);
	printf("heard … ");
	sleep(10);
	printf("about … ");
	sleep(10);
	printf("this … ");
	sleep(10);
	printf("new … ");
	sleep(10);
	printf("CTF … ");
	sleep(10);
	a += 4;
	printf("thingy? ");
	sleep(10);
	printf("Like … ");
	sleep(10);
	printf("a … ");
	sleep(10);
	printf("mix … ");
	sleep(10);
	printf("of … ");
	sleep(10);
	printf("CTF … ");
	sleep(10);
	printf("and … ");
	sleep(10);
	printf("speedrunning. ");
	sleep(10);
	printf("Fastcer 8 … ");
	sleep(10);
	printf("or …");
	sleep(10);
	printf("something … ");
	sleep(10);
	printf("like … ");
	sleep(10);
	printf("this. ");
	sleep(10);
	printf("You … ");
	sleep(10);
	printf("should … ");
	sleep(10);
	a += 1;
	printf("give … ");
	sleep(10);
	printf("it … ");
	sleep(10);
	a /= 2;
	printf("a … ");
	sleep(10);
	printf("try, … ");
	sleep(10);
	printf("it … ");
	sleep(10);
	printf("sounds … ");
	sleep(10);
	printf("like … ");
	sleep(10);
	printf("a … ");
	sleep(10);
	printf("lot … ");
	sleep(10);
	printf("of … ");
	sleep(10);
	printf("fun\n");
	sleep(10);
	a +=3;
	printf("Anyway, … ");
	sleep(10);
	printf("here … ");
	sleep(10);
	printf("is … ");
	sleep(10);
	printf("your … ");
	sleep(10);
	printf("flag %s", " ");
	sleep(10);
	return 0;
}
