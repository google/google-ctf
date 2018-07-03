/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/syscall.h>

#include "sandbox.h"

#define MAX_PATH        (1337 - 1080)

static int access_ok(const void *p, size_t size)
{
  unsigned long addr;

  addr = (unsigned long)p;
  if (addr >= (1L << 32) || addr + size >= (1L << 32) || addr + size < addr)
    return 0;

  return 1;
}

static int op_read(int fd, char *p, size_t size)
{
  if (!access_ok(p, size))
    return -1;

  return syscall(__NR_read, fd, p, size);
}

static int op_write(int fd, const char *p, size_t size)
{
  if (!access_ok(p, size))
    return -1;

  return syscall(__NR_write, fd, p, size);
}

int path_ok(char *pathname, const char *p)
{
  if (!access_ok(p, MAX_PATH))
    return 0;

  memcpy(pathname, p, MAX_PATH);
  pathname[MAX_PATH - 1] = '\x00';

  if (strstr(pathname, "flag") != NULL)
    return 0;

  return 1;
}

static int op_open(const char *p)
{
  char pathname[MAX_PATH];

  if (!path_ok(pathname, p))
    return -1;

  return syscall(__NR_open, pathname, O_RDONLY);
}

static int op_close(int fd)
{
  return syscall(__NR_close, fd);
}

static int op_exit_group(int status)
{
  return syscall(__NR_exit_group, status);
}

int kernel(unsigned int arg0, unsigned int arg1, unsigned int arg2,
           unsigned int arg3)
{
  int ret = 0;

  switch (arg0) {
    case __NR_read:
      ret = op_read(arg1, (char *)((long)arg2), arg3);
      break;

    case __NR_write:
      ret = op_write(arg1, (const char *)((long)arg2), arg3);
      break;

    case __NR_open:
      ret = op_open((const char *)((long)arg1));
      break;

    case __NR_close:
      ret = op_close(arg1);
      break;

    case __NR_mprotect:
      /* no way */
      ret = -1;
      break;

    case __NR_exit_group:
      ret = op_exit_group(arg1);
      break;

    default:
      ret = -1;
      break;
  }

  return ret;
}
