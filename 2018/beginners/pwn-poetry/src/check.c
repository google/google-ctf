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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
  char c;
  int fd;

  fd = open("/proc/sys/fs/protected_hardlinks", O_RDONLY);
  if (fd == -1)
    err(EXIT_FAILURE, "[FAIL] open");

  if (read(fd, &c, sizeof(c)) != sizeof(c))
    err(EXIT_FAILURE, "[FAIL] read");

  close(fd);

  if (c != '0')
    errx(EXIT_FAILURE, "[FAIL] see requirements (README.md)");

  return EXIT_SUCCESS;
}
