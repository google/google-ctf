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
#include <time.h>
#include <pthread.h>

int decrypt(char* flag){
	for(int i=0; flag[i]; i++) {
		flag[i] = flag[i] - 1;
	}
	return 0;
}

static inline size_t strlen(const char* a) {
	size_t i =0 ;
	while(a[i++]) ;
	return i;
}

static inline int strcmp(const char* a, const char* b){
	if (strlen(a) != strlen(b) )
		return 1;
	for(int i=0; i<strlen(a); i++)
		if (a[i] != b[i])
			return 1;
	return 0;
}


int main(int argc, char** argv){
	if(argc != 2) {
		puts("param");
		return 0;
	}
	char flag[] = {'I', 'D', 'M', '9', '|', 'X', 'p', 'p', 'e', 'z', '`', 'x', '1', '1', 'e', '`', 'q', 'b', 'd', 'l', 'f', 's', '~', '\0'};
	decrypt(flag);

	if(strcmp(flag, argv[1]) == 0 )
		puts("WIN");
	else
		puts("LOSE");
}
