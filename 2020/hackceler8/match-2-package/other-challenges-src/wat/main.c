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
#include <stdlib.h>
#include <stdio.h>

int main( int argc, char** argv) {
	if (argc != 3) {
		printf("Usage: %s <num1> <num2>\n");
		return 0;
	}

	unsigned int x = strtoul(argv[1], 0L, 10);
	unsigned int y = strtoul(argv[2], 0L, 10);
	unsigned int bak = x;

	unsigned int sum, carry;
	sum = x ^ y; // x XOR y
	carry = x & y; // x AND y
	while (carry != 0) {
		carry = carry << 1;
		x = sum; 
		y = carry;
		sum = x ^ y;
		carry = x & y; 
	}

	if (bak == 1337 && sum == 13377331) {
		printf("Flag: HCL8{The_magical_number_is_%d}\n", y);
	} else {
		puts("Nope.");
	}
	return 0;
}
