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
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdlib.h>

struct handler {
  void (*pass)(char *admin_password);
  char *(*user)(void);
  void (*list)(void);
};

int __attribute__ ((noinline)) mystrcmp(char *a, char *b) {
  for (int n = 0;; n++) {
    if (a[n] != b[n]) return 0;
    if (a[n] == 0) return 1;
  }
}

size_t __attribute__ ((noinline)) readn(int fd, char *buf, size_t size) {
  size_t pos;
  for (pos = 0; pos < size; pos++) {
    char b;
    if (read(fd, &b, 1) <= 0) {
      _exit(0);
    }

    if (b == '\n') {
      break;
    }
    buf[pos] = b;
  }

  return pos;
}

int __attribute__ ((noinline)) menu(struct handler* handle) {
  char menu[128+1];
  char *password = NULL;

  for(;;) {
    memset(menu, 0, sizeof(menu));
    readn(0, menu, sizeof(menu)-1);

    if (mystrcmp(menu, "USER")) {
      if (password != NULL) _exit(0);
      password = handle->user();
    } else if (mystrcmp(menu, "PASS")) {
      handle->pass(password);
    } else if (mystrcmp(menu, "LIST")) {
      handle->list();
    }
  }
}

void __attribute__ ((noinline)) list_func(void) {
  DIR *dir = opendir("db");
  struct dirent *ent;
  if (dir == NULL) _exit(0);

  while ((ent = readdir(dir)) != NULL) {
    if (ent->d_name[0] == '.') continue;
    puts(ent->d_name);
  }
  closedir(dir);
}

char * __attribute__ ((noinline)) read_file(char *file) {
  char buf[4096+1] = {0};
  int fd = open(file, O_RDONLY);
  if (fd == -1) _exit(0);
  readn(fd, buf, sizeof(buf)-1);
  close(fd);
  return strdup(buf);
}

char * __attribute__ ((noinline)) user_func(void) {
  char myuser[3 + 128+1] = { 'd', 'b', '/' };
  readn(0, &myuser[3], sizeof(myuser)-1-3);
  if (strchr(&myuser[3], '/') != NULL) _exit(0);

  return read_file(myuser);
}

void __attribute__ ((noinline)) pass_func(char *admin_password) {
  char mypassword[128] = {0};
  if (readn(0, mypassword, 4096) % 8 != 0) _exit(0);
  if (mystrcmp(mypassword, admin_password)) {
    _exit(system("cat flag.txt"));
  }
}

int main() {
  struct handler handle = { .pass = pass_func, .user = user_func, .list = list_func };
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  menu(&handle);
}
