// Copyright 2021 Google LLC
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
#include <stdlib.h>
#include <string.h>

void error(char* s) {
	printf("ERROR: %s\n", s);
	exit(1);
}

void printhex(char* str, size_t sz) {
	while (sz--) {
		unsigned char c = *str++;
		printf("%02x", c);
	}
	printf("\n");
}

// No intended bugs here!
size_t compress(char* dst, size_t dst_sz, char* src, size_t src_sz) {
	size_t dst_pos = 0;
	size_t src_pos = 0;

#define EMIT(x) \
	do { \
		if (dst_pos >= dst_sz) { error("destination overflow"); } \
		dst[dst_pos++] = (x); \
	} while (0)

#define EMIT_VARINT(x) \
	do { \
		size_t tmp = (x); \
		do { \
			if (tmp >= 128) { \
				EMIT(128 | (tmp & 0x7f)); \
			} \
			else { \
				EMIT(tmp & 0x7f); \
			} \
			tmp >>= 7; \
		} while (tmp > 0); \
	} while (0)

	EMIT('T');
	EMIT('I');
	EMIT('N');
	EMIT('Y');
	while (src_pos < src_sz) {
		// Check if we have a repetition.
		size_t best_len = 0;
		size_t best_start = 0;
		for (size_t start = 0; start < src_pos; start++) {
			size_t len = 0;
			while (1) {
				if (start + len >= src_sz) break;
				if (src[start + len] != src[src_pos + len]) break;
				len++;
			}
			if (len > best_len) {
				best_len = len;
				best_start = start;
			}
		}
		if (best_len > 3) {
			// Emit repetition.
			size_t delta = src_pos - best_start;
			//printf("Emit repetition: len=%zu, delta=%zu\n", best_len, delta);
			src_pos += best_len;
			EMIT(0xff);
			EMIT_VARINT(delta);
			EMIT_VARINT(best_len);
		}
		else {
			// Emit literal.
			//printf("Emit literal: %02x (%c)\n", src[src_pos], src[src_pos]);
			EMIT(src[src_pos]);
			if (src[src_pos] == 0xff) {
				// Fake rep (0, 1)
				EMIT_VARINT(0);
				EMIT_VARINT(1);
			}
			src_pos++;
		}
	}
	// Fake rep (0, 0)
	EMIT(0xff);
	EMIT_VARINT(0);
	EMIT_VARINT(0);
	return dst_pos;
}

size_t decompress(char* dst, size_t dst_sz, char* src, size_t src_sz) {
	size_t src_pos = 0;
	size_t dst_pos = 0;
		//printf("src_pos=%p\n", &src_pos);

#define POP(x) \
	do { \
		if (src_pos >= src_sz) error("input underflow"); \
		x = src[src_pos++]; \
	} while (0)

#define POP_VARINT(x) \
	do { \
		x = 0; \
		int shift = 0; \
		while (1) { \
			unsigned char cc; \
			POP(cc); \
			x |= ((size_t)(cc & 0x7fu)) << shift; \
			shift += 7; \
			if (!(cc & 128)) { \
				break; \
			} \
		} \
	} while (0)

	unsigned char c;
	POP(c);
	if (c != 'T') error("bad magic");
	POP(c);
	if (c != 'I') error("bad magic");
	POP(c);
	if (c != 'N') error("bad magic");
	POP(c);
	if (c != 'Y') error("bad magic");
	while (1) {
		POP(c);
		if (c != 0xff) {
			EMIT(c);
			//printf("lit(%02x)\n", c);
		}
		else {
			size_t delta, length;
			POP_VARINT(delta);
			POP_VARINT(length);
			//printf("rep(%zd %zd)\n", delta, length);
			if (delta != 0) {
				// Here's the bug: delta and length not validated.
				//memmove(dst + dst_pos, dst + dst_pos - delta, length);
				//dst_pos += length;
				for (size_t i = 0; i < length; i++) {
					dst[dst_pos] = dst[dst_pos - delta];
					dst_pos++;
				}
			}
			else {
				if (length == 0) {
					break;
				}
				else if (length == 1) {
					EMIT(0xff);
				}
				else {
					error("invalid special command");
				}
			}
		}
	}
	return dst_pos;
}

int chrdehex(char c) {
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	error("invalid hexadecimal digit");
}

size_t dehex(char* src) {
	size_t i;
	for (i = 0; src[i]; i += 2) {
		int c1 = chrdehex(src[i]);
		int c2 = chrdehex(src[i+1]);
		src[i/2] = c1*16+c2;
	}
	return i/2;
}

int main() {
	setvbuf(stdin,NULL,_IONBF,0);
	setvbuf(stdout,NULL,_IONBF,0);
	setvbuf(stderr,NULL,_IONBF,0);
	// Force stack layout...
	struct {
		char command[256];
		char password[256];
		char expected_password[256];
		char src[8192];
		char dst[4096];
	} x;
	char* src = x.src;
	char* dst = x.dst;
	char* command = x.command;
	char* password = x.password;
	char* expected_password = x.expected_password;
	strcpy(command, "cat FORMAT.md");

	printf("What can I do for you?\n");
	printf("1. Compress string\n");
	printf("2. Decompress string\n");
	printf("3. Read compression format documentation\n");
	printf("\n");
	int choice = 0;
	if (scanf("%d", &choice) != 1) {
		error("invalid choice");
	}
	if (choice == 1) {
		printf("Send me the hex-encoded string (max 4k):\n");

		scanf("%8000s", src);
		size_t src_sz = dehex(src);

		size_t sz = compress(dst, 4000, src, src_sz);
		printf("These %zu bytes compress to %zu bytes (%.2lf%%):\n",
				src_sz, sz, 100.0 * sz / src_sz);
		printhex(dst, sz);
	}
	else if (choice == 2) {
		printf("Send me the hex-encoded string (max 4k):\n");

		scanf("%8000s", src);
		size_t src_sz = dehex(src);

		//printf("dst    =%p, cmd=%p\n", dst, command);
		size_t sz = decompress(dst, 4000, src, src_sz);
		printf("That decompresses to:\n");
		printhex(dst, sz);

	}
	else if (choice == 3) {
		printf("Format documentation is password protected.\n");
		printf("Input password:\n");
		scanf("%100s", password);
		FILE* f = fopen("FORMAT.md.password", "r");
		fscanf(f, "%s", expected_password);
		if (0 != strcmp(password, expected_password)) {
			error("wrong password");
		}
		else {
			system(command);
		}
	}
	else {
		error("invalid choice");
	}
}
