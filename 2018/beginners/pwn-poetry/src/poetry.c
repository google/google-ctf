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

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
  char buf[PATH_MAX];
  ssize_t size;

  /* Ensure that all relocations are made by the loader. That obviously asserts
   * that strcpy will behave as expected ;-) */
  if (!getenv("LD_BIND_NOW")) {
    size = readlink("/proc/self/exe", buf, sizeof(buf));
    if (size == -1)
      err(1, "readlink");

    if (setenv("LD_BIND_NOW", "1", 1) != 0)
      err(1, "setenv");

    buf[PATH_MAX - 1] = '\x00';
    if (execv(buf, argv) != 0)
      err(1, "execv");
  }

  if (argc == 2) {
    printf("o/\n");
    strcpy(buf, argv[1]);
    asm("xor %rdi, %rdi\nmov $231, %rax\nsyscall\n");
  }

  return 0;
}
