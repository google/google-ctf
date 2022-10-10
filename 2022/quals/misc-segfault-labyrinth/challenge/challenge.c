// Copyright 2022 Google LLC
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

// Author: Carl Svensson

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <linux/seccomp.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#ifdef DEBUG
    #include <sys/stat.h>
#endif

#include "seccomp-bpf.h"

extern char _binary_prologue_start[], _binary_prologue_end[];
#define PROLOGUE_LEN (_binary_prologue_end - _binary_prologue_start)

#define PAGE_SIZE 0x1000
#define NUM_LAYERS 10
#define LAYER_SIZE 16


static int install_filter() {
  struct sock_filter filter[] = {
		/* Validate architecture. */
		VALIDATE_ARCHITECTURE,
		/* Grab the system call number. */
		EXAMINE_SYSCALL,
		/* List allowed syscalls. */
		ALLOW_SYSCALL(rt_sigreturn),
#ifdef __NR_sigreturn
		ALLOW_SYSCALL(sigreturn),
#endif
		ALLOW_SYSCALL(exit_group),
		ALLOW_SYSCALL(exit),
		ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),
        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(stat),
		ALLOW_SYSCALL(write),
		KILL_PROCESS,
	};
  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("prctl(NO_NEW_PRIVS)");
    return 1;
  }
  if (prctl(PR_SET_SECCOMP, 2, &prog)) {
    perror("prctl(PR_SET_SECCOMP)");
    return 1;
  }
  return 0;
}


unsigned long long** generate_layer(unsigned long long** pointers, FILE* urandom, size_t pages) {
    // Generate correct index
    unsigned char correct_idx;
    size_t rand_read = fread(&correct_idx, sizeof(unsigned char), 1, urandom);
    correct_idx %= LAYER_SIZE;
    #ifdef DEBUG
    fprintf(stderr, "Correct index: %d\n", correct_idx);
    #endif
    if(rand_read != 1) {
        fprintf(stderr, "Error: failed to read random. Exiting.\n");
        return NULL;
    }

    // allocate pages
    for(size_t i = 0; i < pages; i++) {
        int prot;
        if(i == correct_idx) {
            prot = PROT_READ | PROT_WRITE;
        } else {
            prot = PROT_NONE;
        }
        
        void* chunk_address = (void*)(0x10000ULL + (((uint64_t)rand()) << 12));
        pointers[i] = (unsigned long long*)mmap(chunk_address, PAGE_SIZE, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if(pointers[i] == NULL) {
            fprintf(stderr, "Error: failed to allocate memory.\n");
            return NULL;
        }
    }

    return (unsigned long long **)pointers[correct_idx];
}

#ifdef DEBUG
int valid_pointer(unsigned long *addr) {
    int fd = open((char*)addr, 0);
    //fprintf(stderr, "fd: %d, errno: %d\n", fd, errno);
    if(fd != -1) {
        close(fd);
        return 1;
    }
    return errno != 14;
}


int valid_pointer2(unsigned long *addr) {
    int num_written = syscall(SYS_write, stdout, 1, addr);
    return num_written == 1;
}


int valid_pointer3(char *addr) {
    struct stat tmp;
    //stat((char*)addr, &tmp);
    syscall(SYS_stat, (char*)addr, &tmp);
    return errno != 14;
}


void test(unsigned long long **pointers) {
    for(size_t i = 0; i < NUM_LAYERS; i++) {
        printf("Layer: %p,", pointers);
        for(size_t j = 0; i < LAYER_SIZE; j++) {
            if(valid_pointer3((char *)pointers[j])) {
                printf(" index: %ld\n", j);
                pointers = (unsigned long long **)pointers[j];
                break;
            }
        }
    }
    printf("Flag: %s\n", (char*)pointers);
}
#endif


size_t read_data(int fd, void *dst, size_t length) {
    size_t num_read = 0;
    while(num_read < length) {
        num_read += read(fd, dst, length - num_read);
    }
    return num_read;
}


int main() {
    if(setvbuf(stdout, NULL, _IONBF, 0)) {
        fprintf(stderr, "Error: failed to disable output buffering. Exiting\n");
        return -1;
    }
    if(setvbuf(stdin, NULL, _IONBF, 0)) {
        fprintf(stderr, "Error: failed to disable input buffering. Exiting\n");
        return -1;
    }
    
    FILE *urandom = fopen("/dev/urandom", "r");
    if(urandom == NULL) {
        fprintf(stderr, "Error: failed to open urandom. Exiting\n");
        return -1;
    }

    // Create layers
    // Note: start_array also needs to be allocated elsewhere otherwise it could be used to leak stack location and potentially lead to unintended solutions
    unsigned long long** start_array = (unsigned long long**)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned long long** current_layer = start_array;
    for(size_t i = 0; i < NUM_LAYERS; i++) {
        current_layer = generate_layer(current_layer, urandom, LAYER_SIZE);
        if(current_layer == NULL) {
            fprintf(stderr, "Error: failed to build labyrinth. Exiting\n");
            return -1;
        }
    }
    fclose(urandom);

    // Read flag
    FILE *flag = fopen("flag.txt", "r");
    if(flag == NULL) {
        fprintf(stderr, "Error: failed to open flag. Exiting.\n");
        return -1;
    }
    size_t num_read = fread(current_layer, 1, PAGE_SIZE, flag);
    if(num_read == 0) {
        fprintf(stderr, "Error: failed to read flag. Exiting.\n");
        return -1;
    }
    fclose(flag);

    // Read shellcode
    unsigned char *shellcode = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(shellcode == NULL) {
        fprintf(stderr, "Error: failed to allocate shellcode memory. Exiting.\n");
        return -1;
    }
    memcpy(shellcode, _binary_prologue_start, PROLOGUE_LEN);
    
    printf("Welcome to the Segfault Labyrinth\n");
    install_filter();

#ifdef DEBUG
    test(start_array);
#endif

    size_t shellcode_size;
    //num_read = fread(&shellcode_size, sizeof(size_t), 1, stdin);
    num_read = read_data(STDIN_FILENO, &shellcode_size, sizeof(size_t));
    if(num_read != sizeof(size_t)) {
        fprintf(stderr, "Error: failed to read code size. Exiting.\n");
        return -1;
    }

    shellcode_size = shellcode_size % (PAGE_SIZE - PROLOGUE_LEN);
    //num_read = fread(&shellcode[PROLOGUE_LEN], shellcode_size, 1, stdin);
    num_read = read_data(STDIN_FILENO, &shellcode[PROLOGUE_LEN], shellcode_size);
    if(num_read != shellcode_size) {
        fprintf(stderr, "Error: failed to read code. Exiting.\n");
        return -1;
    }

    ((void (*)(unsigned long long**))shellcode)(start_array);
    
    return 0;
}
