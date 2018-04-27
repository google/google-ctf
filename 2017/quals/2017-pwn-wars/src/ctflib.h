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



/*
 ============================================================================
 Name        : ctflib.h
 Author      : Steven Vittitoe (scvitti@)
 Version     : 0.1
 ============================================================================
 */

#ifndef _CTFLIB_INC
#define _CTFLIB_INC
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <err.h>
#include <time.h>

typedef int (*callback)(int client_sock);
void sigchld(int sig);
int readAll(int fd, unsigned char *buf, unsigned int size);
int read_until_delim(int fd, char *buf, unsigned int size, char endchar);
int sendMsg(int fd, const char *buf, int nullflag);
int sendAll(int fd, unsigned char *buf, unsigned int size);
int sendFormat(int fd, const char *format, ...);
int init(int port);
void loop(int server_sock, callback client_func);
int drop_privs_user(const char *user_name);
int drop_privs(struct passwd *pw);
int get_choice(int sock, int min, int max);
int get_random_int(int min_num, int max_num);

#endif
