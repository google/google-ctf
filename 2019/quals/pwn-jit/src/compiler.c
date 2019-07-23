/**
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>

typedef struct {
  void *text;
  void *data;
} jit_t;

void* rand_page() {
  uint64_t res = 0;
  for (int i = 0; i < 3; i++) {
    res = (res << 16) ^ rand();
  }
  res = res & 0x00007FFFFFFFFFFF;
  return (void*)(res & ~0xfffLL);
}

int jit_init(jit_t* jit) {
  void* pages[2] = {NULL, NULL};
  for (int i = 0; i < 2; i++) {
    while (pages[i] == NULL) {
      void* page = rand_page();
      void* mmapped = mmap(page, 4096, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
      // printf("mmap(%p) = %p\n", page, mmapped);
      if (mmapped == MAP_FAILED || mmapped != page) {
        continue;
      }
      pages[i] = mmapped;
    }
  }
  jit->text = pages[0];
  jit->data = pages[1];
  return 0;
}

int intbracket(const char* s) {
  int mul = 1;
  if (*s == '-' || *s == '+') {
	  mul = (*s == '-') ? -1 : 1;
	  s++;
  }
  int res = 0;
  for (; *s != ')'; s++) {
    res = res * 10 + *s - '0';
  }
  return res * mul;
}

void compile1(const char* cmd, char* out, int instrno) {
  if (strncmp(cmd, "MOV", 3) == 0) {
    if (cmd[4] == 'A') { // MOV(A, 100)
      out[0] = 0xb8; // mov eax, imm32
      *((int*)(out + 1)) = intbracket(cmd + 7);
    } else { // MOV(B, 100)
      out[0] = 0xbb; // mov ebx, imm32
      *((int*)(out + 1)) = intbracket(cmd + 7);
    }
  } else if (strncmp(cmd, "ADD", 3) == 0) {
    out[0] = 0x05; // add eax, imm32
    *((int*)(out + 1)) = intbracket(cmd + 7);
  } else if (strncmp(cmd, "SUB", 3) == 0) {
    out[0] = 0x2d; // sub eax, imm32
    *((int*)(out + 1)) = intbracket(cmd + 7);
  } else if (strncmp(cmd, "SUM", 3) == 0) {
    out[0] = 0x01;
    out[1] = 0xd8; // add eax, ebx
    out[2] = 0x90; // nop x3
    out[3] = 0x90;
    out[4] = 0x90;
  } else if (strncmp(cmd, "CMP", 3) == 0) {
    out[0] = 0x3d; // cmp eax, imm32
    *((int*)(out + 1)) = intbracket(cmd + 7);
  } else if (strncmp(cmd, "LDR", 3) == 0) {
    out[0] = 0x41;
    out[1] = 0x8b;
    if (cmd[4] == 'A') {
      out[2] = 0x44; // mov eax, [r12+imm8]
    } else {
      out[2] = 0x5c; // mov ebx, [r12+imm8]
    }
    out[3] = 0x24;
    out[4] = 4 * intbracket(cmd + 7);
  } else if (strncmp(cmd, "STR", 3) == 0) {
    out[0] = 0x41;
    out[1] = 0x89;
    if (cmd[4] == 'A') {
      out[2] = 0x44; // mov [r12+imm8], eax
    } else {
      out[2] = 0x5c; // mov [r12+imm8], ebx
    }
    out[3] = 0x24;
    out[4] = 4 * intbracket(cmd + 7);
  } else if (strncmp(cmd, "JMP", 3) == 0) {
    out[0] = 0xe2;
    out[1] = 0x01; // loop ->jmp
    out[2] = 0xc3; // ret
    out[3] = 0xeb;
    out[4] = (intbracket(cmd + 4) - instrno) * 5 - 5; // jmp imm8
  } else if (strncmp(cmd, "JEQ", 3) == 0) {
    out[0] = 0xe2;
    out[1] = 0x01; // loop ->jeq
    out[2] = 0xc3; // ret
    out[3] = 0x74;
    out[4] = (intbracket(cmd + 4) - instrno) * 5 - 5; // jeq imm8
  } else if (strncmp(cmd, "JNE", 3) == 0) {
    out[0] = 0xe2;
    out[1] = 0x01; // loop ->jne
    out[2] = 0xc3; // ret
    out[3] = 0x75;
    out[4] = (intbracket(cmd + 4) - instrno) * 5 - 5; // jne imm8
  } else if (strncmp(cmd, "RET", 3) == 0) {
    out[0] = 0xc3; // ret
  } else {
    printf("Unknown instr: %s\n", cmd);
  }
}

int run(const char** program, int programlen) {
  jit_t jit;
  jit_init(&jit);
  for (int i = 0; i < programlen; i++) {
    compile1(program[i], ((char*)jit.text) + 5 * i, i);
  }
  if (mprotect(jit.text, 4096, PROT_READ|PROT_EXEC) != 0) {
    return -1;
  };
  int64_t res = 0;
  __asm(
      "\n\tpush %%r12"
      "\n\tpush %%rbx"
      "\n\tmov $10000, %%rcx"
      "\n\tmov %1, %%rax"
      "\n\tmov %2, %%r12"
      "\n\tcall *%%rax"
      "\n\tpop %%rbx"
      "\n\tpop %%r12"
      "\n\tmov %%rax, %0"
      : "=r"(res)
      : "r"(jit.text), "r"(jit.data)
      : "rax", "rcx", "cc", "memory"
        );
  return (int)res;
}

void init() __attribute__((constructor));
void init() {
  // lol
  srand(time(NULL));
}

int main() {
  const char* prog[] = {
    "MOV(A, 10)",
    "STR(A, 1)",
    "MOV(A, 1)",
    "MOV(B, 1)",
    "STR(A, 2)",
    "STR(B, 3)",
    "LDR(A, 2)",
    "LDR(B, 3)",
    "SUM()",
    "STR(B, 2)",
    "STR(A, 3)",
    "LDR(A, 1)",
    "SUB(A, 1)",
    "STR(A, 1)",
    "CMP(A, 0)",
    "JEQ(17)",
    "JMP(6)",
    "LDR(A, 2)",
    "RET()",
  };
  int res = run(prog, sizeof(prog)/sizeof(prog[0]));
  printf("res = %d\n", res);
}
