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



#include <sys/types.h>
#define LD_PATH "/lib64/ld-linux-x86-64.so.2"

#define SANDBOX_FD 100
#define BROKER_FD 101

#ifndef SYS_memfd_create
# define SYS_memfd_create 319
#endif
#ifndef CLONE_NEWCGROUP
# define CLONE_NEWCGROUP 0x02000000
#endif
#ifndef MFD_CLOEXEC
# define MFD_CLOEXEC       0x0001U
#endif
#ifndef SYS_execveat
# define SYS_execveat 322
#endif

void load_libraries(int broker_fd, int exec_fd);
void copy_file(const char * const in, const char * const out);
void copy_fd_to_file(int in, const char * const out);
void copy_fd(int in, int out);
void copy_fd_len(int in, int out, size_t len);

void make_cloexec(int fd);

ssize_t check(ssize_t ret, const char * const msg);
void *check_malloc(size_t size);
void readn(int fd, void *buf, size_t len);
char *reads(int fd);

void send_fd(int chan, int fd);
void send_str(int chan, char *s);
int recv_fd(int chan);
size_t recv_str(int chan, char *buf, size_t len);
