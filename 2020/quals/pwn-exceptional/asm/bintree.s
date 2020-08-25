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
#define r0 memory[0]
#define r1 memory[1]
#define r2 memory[2]
#define r3 memory[3]
#define r4 memory[4]
#define r5 memory[5]
#define r6 memory[6]
#define r7 memory[7]

#define total_cities r7

#define buf 100
#define flag 200
#define tree 300

// struct node
//  int hash
//  int left
//  int right
//  int time
//  char name[48]

#define sizeof_node 16 // In 4-byte words.
#define MAX_CITIES 100

fun hash_string:
	//printf("[debug] hashing %s\n", memory+r0)
	r1 = 0x12345678
	r2 = 0
	loop {
		if (r2 == 12) {
			break
		}
		r1 ^= memory[r0]
		r0++
		r2++
	}
	//printf("[debug] hash: 0x%08x\n", r1)
	r0 = r1
	return

fun add_city:
	r1 = total_cities
	if (r1 >= MAX_CITIES) {
		printf("City limit reached.\n")
		return
	}
	total_cities++
	r1 *= sizeof_node
	r1 += tree
	printf("Type city name and timezone (e.g. \"NewYork -4\"): ")
	memset(memory+r1+4, 0, 48)
	scanf("%45s %d", memory+r1+4, memory+r1+3)
	memory[r1+2] = -1
	memory[r1+1] = -1
	r0 = r1 + 4
	push(r1)
	call hash_string
	pop(r1)
	memory[r1+0] = r0
	// we have added the new node, we just need to link it well
	if (r1 == tree) {
		return
	}
	r0 = tree
	loop {
		if (memory[r1] == memory[r0]) {
			// Assume hash collision means key collision...
			printf("City already exists.\n")
			total_cities--
			return
		}
		if (memory[r1] <= memory[r0]) {
			// Go to the left child.
			if (memory[r0+1] == -1) {
				memory[r0+1] = r1
				return
			}
			r0 = memory[r0+1]
		}
		if (memory[r1] > memory[r0]) {
			// Go to the right child.
			if (memory[r0+2] == -1) {
				memory[r0+2] = r1
				return
			}
			r0 = memory[r0+2]
		}
	}

fun list_cities:
	r0 = 0
	printf("List of cities:\n")
	loop {
		if (r0 >= total_cities) {
			return
		}
		r1 = r0 * sizeof_node
		r1 += tree
		//printf("[debug] %d (@%d): hash=0x%08x, l=%d, r=%d, tz=%d, name=%s\n", r0+1, r1, memory[r1], memory[r1+1], memory[r1+2], memory[r1+3], memory+r1+4)
		printf("%02d. %s UTC%+02d\n", r0+1, memory+r1+4, memory[r1+3])
		r0++
	}

// The buggy function (recursion stack colliding with array).
fun recursive_find:
	// r0 - hash
	// r1 - current node
	// These pushes are technically not necessary (r0 is not modified,
	// r1 is not needed anymore after the tail call), but are needed for the bug.
	push(r0)
	push(r1)
	//printf("[debug] sptr: %d\n", sptr-memory)
	if (r1 == -1) {
		// Found null node.
		pop(r1)
		pop(r0)
		r0 = -1
		return
	}
	// printf("[debug] cmp hash (%d) with mem[%d] = %d\n", r0, r1, memory[r1])
	if (r0 == memory[r1]) {
		// Found!
		pop(r1)
		pop(r0)
		r0 = r1
		return
	}
	if (r0 < memory[r1]) {
		// Recurse left.
		r1 = memory[r1+1]
		call recursive_find
		pop(r1)
		pop(r1)
		return
	}
	if (r0 > memory[r1]) {
		// Recurse right.
		r1 = memory[r1+2]
		call recursive_find
		pop(r1)
		pop(r1)
		return
	}
	// Shouldn't happen.
	while(1);
	

fun find_in_tree:
	if (total_cities == 0) {
		r0 = -1
		return
	}
	call hash_string
	// Now r0 has the hash.
	r1 = tree
	call recursive_find
	return

fun calculate_time:
	printf("Type your city and current time (e.g. \"NewYork 12:34\"): ")
	memset(memory+buf, 0, 48)
	scanf("%45s %d:%d", memory+buf, &r0, &r1)
	push(r0)
	push(r1)
	r0 = buf
	call find_in_tree
	push(r0)

	printf("Type the other city: (e.g. \"Washington\"): ")
	memset(memory+buf, 0, 48)
	scanf("%45s", memory+buf)
	r0 = buf
	call find_in_tree
	r3 = r0 /* position of the other city */
	pop(r2) /* position of the first city */
	pop(r1)	/* minutes */
	pop(r0) /* hours */
	
	if (r0 < 0 || r0 > 23 || r1 < 0 || r1 > 59) {
		printf("Invalid time format.\n")
		return
	}
	if (r2 == -1 || r3 == -1) {
		printf("Invalid city\n")
		return
	}
	
	// printf("[debug] found cities at %d, %d\n", r2, r3)
	r2 = memory[r2+3]
	r0 -= r2
	r2 = memory[r3+3]
	r0 += r2
	r0 += 24
	r0 %= 24
	printf("Current time in %s: %02d:%02d.\n", memory+r3+4, r0, r1)
	
	return

fun start:
	// "flag.txt"
	memory[buf] = 0x67616c66
	memory[buf+1] = 0x7478742e
	r0 = open((char*)(memory + buf), O_RDONLY)
	read(r0, memory + flag, 64)
	printf("Welcome to city timezone calculator.\n\n")
	loop {
		printf("Menu:\n")
		printf("1. Add city\n")
		printf("2. List cities\n")
		printf("3. Calculate time\n")
		printf("4. Quit\n")
		r1 = scanf("%d", &r0)
		if (r1 != 1) {
			printf("Invalid choice\n")
			return
		}
		if (r0 == 1) {
			push(r0)
			call add_city
			pop(r0)
		}
		if (r0 == 2) {
			push(r0)
			call list_cities
			pop(r0)
		}
		if (r0 == 3) {
			push(r0)
			call calculate_time
			pop(r0)
		}
		if (r0 == 4) {
			return
		}
		if (r0 < 1 || r0 > 4) {
			printf("Invalid choice\n")
			return
		}
	}
