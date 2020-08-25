/*
 * Copyright 2020 Google LLC
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

// <<<<<<<<<<<<<<<<<<<<<<<<<<<<< DEBUG ONLY >>>>>>>>>>>>>>>>>>>>>>>>>>>>>
//#define INSECURE 1

#define KEY_GATE_STACK_SIZE (1024*1024)
#define TRUSTED_KEY_STATE_PLACEHOLDER 0x12345678
#define NORMAL_KEY_STATE_PLACEHOLDER 0x87654321

#ifndef __ASSEMBLER__
extern char key_gate_stack[KEY_GATE_STACK_SIZE] __attribute__((aligned(4096)));

extern unsigned int gatekey_trusted_key_state;
extern unsigned int gatekey_normal_key_state;

extern char _gatekey_text_begin[];
extern char _gatekey_text_end[];
extern char _gatekey_data_begin[];
extern char _gatekey_data_end[];
extern char _gatekey_bss_begin[];
extern char _gatekey_bss_end[];
extern char _end[];

unsigned long gatekey_exit_trusted(unsigned long retval);
unsigned long gatekey_syscall(unsigned long arg1, unsigned long arg2,
                              unsigned long arg3, unsigned long arg4,
                              unsigned long arg5, unsigned long nr);


#define AT_FDCWD -100

#include <linux/seccomp.h>
#define __NR_openat2 437
struct open_how {
  __u64 flags;
  __u64 mode;
  __u64 resolve;
};

/* how->resolve flags for openat2(2). */
#define RESOLVE_NO_XDEV   0x01 /* Block mount-point crossings
          (includes bind-mounts). */
#define RESOLVE_NO_MAGICLINKS 0x02 /* Block traversal through procfs-style
          "magic-links". */
#define RESOLVE_NO_SYMLINKS 0x04 /* Block traversal through all symlinks
          (implies OEXT_NO_MAGICLINKS) */
#define RESOLVE_BENEATH   0x08 /* Block "lexical" trickery like
          "..", symlinks, and absolute
          paths which escape the dirfd. */
#define RESOLVE_IN_ROOT   0x10 /* Make all jumps to "/" and ".."
          be scoped inside the dirfd
          (similar to chroot(2)). */
/* END */

#define GATEKEY_OP_OPEN 1
#define GATEKEY_OP_CREATE 2

struct gatekey_args {
  unsigned long op;
  char *path;
  char authkey[64];
};

unsigned long gatekey_call(struct gatekey_args *args);

#endif
