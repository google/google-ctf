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
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

char outbuf[1<<24];
char* memory;
uint16_t* dptr;

// MOV reg_X, imm
// JUMP imm
void set_reg() {
	uint16_t a, pc;
	sprintf(outbuf, "%1$123s%2$hn", "", &a);
	printf("set: a = %hd\n", a);
}

// ADD reg_X, reg_Y + reg_Z/imm
void add(uint16_t a, uint16_t b) {
	uint16_t c;
	sprintf(outbuf, "%1$*2$s%1$*3$s%4$hn", "", a, b, &c);
	printf("add: c = %hd\n", c);
}

// JUMP imm if check==0, else JUMP imm.
void branch_zero(uint16_t check) {
	uint16_t pc = 0x9001;
	// Set pc to 581 or 705, depending on check==0.
	// 581 = 456 + 123 + 2 (one for \0, one for check byte) - go there if 0
	// 705 = 581 + 123 + 1 - go there if != 0
	//
	// In other words, to jump to A or B, the constants should be:
	// first = B-A-1
	// second = A-2-first = A-2-(B-A-1) = 2*A-B-1
	//
	// It works by printing (%s) the very same buffer we output to.
	// We first conditionally terminate it by putting NUL byte,
	// then terminating it unconditionally some spaces later.
	//
	// Since this operates on byte-sized register, the check-register
	// will have to be special, kind of like AX in x86:
	// accessible as AX for normal instructions, and as
	// AH or AL for the purposes of this instruction.
	//
	// Another option is to abuse store/load instructions
	// for unaligned writes and select just the low byte.
	sprintf(outbuf, "%2$c%1$123s%5$c%3$s%1$456s%4$hn", "", check, outbuf, &pc, 0);
	printf("branch if LO(%d) == 0: pc = %hd\n", check, pc);
}
// Non-branching instructions have to contain a pc++ equivalent.
// Since we don't bother with position-independent code etc, this
// can be done by just setting pc=next_instruction. This, in turn
// is done by printing N spaces, %n'ing the &pc and printing
// 2**16-N spaces to reset the counter for all intents and purposes.

// mem[reg_X] = reg_Y
void store(uint16_t x, uint16_t y) {
	sprintf(outbuf, "%1$*3$s%2$hn", "", &dptr, x);
	sprintf(outbuf, "%1$*3$s%2$hn", "", dptr, y);
	printf("stored 0x%x at %d\n", y, x);
}

// reg_Y = mem[reg_X]
void load(uint16_t x) {
	// This is going to have two phases.
	uint16_t y = 0x9001;
	// 1. MOV dptr, x
	sprintf(outbuf, "%1$*3$s%2$hn", "", &dptr, x);
	// 2. MOV y, *dptr
	sprintf(outbuf, "%1$*2$s%3$hn", "", *dptr, &y);
	printf("load: [%d] = 0x%x\n", x, y);
}


// So far, the final printf call will have to contain the following arguments:
// "", 0, dptr, &dptr, *dptr, outbuf, &pc, &reg1, reg1, &reg2, reg2, ...
int main() {
	memory = mmap((char*)0x1000000, 1<<24, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	char* program = mmap((char*)0x2000000, 1<<24, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	dptr = (uint16_t*)memory;
	printf("mem at %p\n", memory);
	set_reg();
	add(3, 5);
	branch_zero(0);
	branch_zero(256);
	branch_zero(1);
	branch_zero(257);
	load(123);
	load(124);
	load(125);
	store(124, 0x203);
	load(123);
	load(124);
	load(125);
	printf("Now a simple proof of concept, a program that adds two numbers\n");
	printf("and checks whether the sum is 1337.\n");
	printf("Give two numbers:\n");
	scanf("%hd %hd", memory, memory+2);
	printf("mem %d\n", memory[0]);
	const char fmt[] =
		/* update pc             instruction */
		"%1$31s%3$hn%1$65505s"  "%1$0s%7$hn\x00"    // dptr = 0
		"%1$64s%3$hn%1$65472s"  "%1$*5$s%9$hn\x00"  // r0 = *dptr
		"%1$95s%3$hn%1$65441s"  "%1$2s%7$hn\x00"    // dptr = 2
		"%1$130s%3$hn%1$65406s" "%1$*5$s%11$hn\x00" // r1 = *dptr
		"%1$172s%3$hn%1$65364s" "%1$*8$s%1$*10$s%9$hn\x00"  // r0 = r0 + r1
		"%1$215s%3$hn%1$65321s" "%1$*8$s%1$64199s%9$hn\x00" // r0 = r0 + (65536-1337)
		
		"%8$c%1$152s%2$c%4$s%1$093s%3$hn\x00"       // jump later if r0 != 0
		"%1$279s%3$hn%1$65257s" "%1$1s%9$hn\x00"    // r0 = 1
		"%1$65535s%3$hn\x00"                        // halt
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"%1$432s%3$hn%1$65104s" "%1$0s%9$hn\x00"    // r0 = 0
		"%1$65535s%3$hn\x00"                        // halt
		"";
	// sprintf(outbuf, "%2$c%1$123s%5$c%3$s%1$456s%4$hn", "", check, outbuf, &pc, 0);
	memcpy(program, fmt, sizeof(fmt));
	const char* volatile pc = program;
	int i = 0;
	volatile uint16_t reg[20] = {0x0};
	printf("end code: %p\n", program + 0xffff);
	while (pc != program + 0xffff) {
		if (i++ >= 13) {
			break;
		}
		printf("[trace] pc = %p\n", pc);
		printf("[trace] ins = %s\n", pc);
		printf("[trace] dptr = %04x; r0 = %04x; r1 = %04x\n", dptr, reg[0], reg[1]);
		sprintf(outbuf, pc, 
				"", // 1$
				0, // 2$
				&pc, // 3$
				outbuf, // 4$
				*dptr, // 5$
				dptr, // 6$
				&dptr, // 7$
				reg[0], reg+0, // 8-9$
				reg[1], reg+1 // 10-11$
		);
		printf("\n");
	}
	if (reg[0]) {
		printf("Hey, correct!\n");
	}
	else {
		printf("Nope.\n");
	}
}

// assembly snippets & ideas:
//
// check reg1 == 0:
// ----------------
// mem[2] = reg1
// reg2 = mem[2]
// jump notzero if reg2.l != 0
// reg2 = mem[3]
// jump notzero if reg2.l != 0
// jump iszero
//
// subtract reg1-reg2:
// by repeated decrementation, not too efficient...
// ------------------
// lp:
// jump end if reg2 == 0
// reg1 += -1 ; or +1 for efficiency if you know they are likely negative
// reg2 += -1 ; or +1
// jump lp
//
// jump if reg1 <= reg2:
// -------------------
// lp:
// jump true if reg1 == 0
// jump false if reg2 == 0
// reg1 += -1
// reg2 += -1
// jump lp
//
// divide reg1 /= reg2:
// -----------
// reg3 = 0
// reg2 = 0 - reg2
// lp:
// jump end if reg1 < 0
// reg3 += 1
// reg1 += reg2
//
// some common unary operations can be tabulated at startup
// - definitely the "is byte < 0" (>=0x80), which can be easily
// used to determine the same for the whole word (by misaligning stores).
