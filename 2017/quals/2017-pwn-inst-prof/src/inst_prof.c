/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



#error "don't recompile this without triple checking it's still exploitable! the tester exploit relies on a particular register allocation and rop gadget offsets"
/*
This service is an instruction profiler

It reads four bytes of input from the user and executes those four bytes
0x1000 times and returns the difference between rdtsc before and after.
*/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <x86intrin.h>

#define PAGE_SIZE 0x1000

uint8_t* alloc_page() {
  uint8_t* buf = mmap(NULL,
                      PAGE_SIZE,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS,
                      -1,
                      0);
  return buf;
}

void make_page_executable(uint8_t* page) {
  mprotect(page, PAGE_SIZE, PROT_READ|PROT_EXEC); 
}

void free_page(uint8_t* page) {
  munmap(page, PAGE_SIZE);
}

uint8_t read_byte() {
  uint8_t val = 0;
  ssize_t amount_read = read(0, &val, 1);
  if (amount_read != 1) {
    exit(EXIT_SUCCESS);
  }
  return val;
}

void read_n(uint8_t* buf, size_t n) {
  for (size_t i = 0; i < n; i++) {
    buf[i] = read_byte();
  }
}

/* read 4 bytes from input into mem */
void read_inst(uint8_t* mem) {
  read_n(mem, 4);
}

const uint8_t template[] = {
  0xb9, 0x00, 0x10, 0x00, 0x00, // mov ecx, 0x1000
  0x90,                         // nop
  0x90,                         // nop
  0x90,                         // nop
  0x90,                         // nop
  0x83, 0xe9, 0x01,             // sub ecx, 1
  0x75, 0xf7,                   // jnz loop
  0xc3                          // ret
};
#define template_instr_offset 5

void do_test() {
  uint8_t* mem = alloc_page();
  memcpy(mem, template, sizeof(template));
  read_inst(mem+template_instr_offset);
  
  make_page_executable(mem);

  uint64_t before = __rdtsc();  

  ((void(*)())mem)();

  uint64_t after = __rdtsc();  

  uint64_t result = after - before;
  ssize_t amount_written = write(1, &result, 8);
  if (amount_written != 8) {
    exit(EXIT_SUCCESS);
  }

  free_page(mem);
}

int main(int argc, char** argv) {
  // you're not meant to brute force this challenge!
  ssize_t n = write(1, "initializing prof...", 20);
  if (n != 20) {
    exit(EXIT_SUCCESS);
  }

  sleep(5);
  alarm(30);

  n = write(1, "ready\n", 6);
  if (n != 6) {
    exit(EXIT_SUCCESS);
  }
   
  while (1) {
    do_test();
  }
  return 0;
}
