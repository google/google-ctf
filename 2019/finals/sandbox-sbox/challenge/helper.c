/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <limits.h>

char g_flag[35];
char g_buf[256];
char line[1024];

#define CHECK(q)     \
  do {               \
    if (!(q)) {      \
      write_error(); \
      return;        \
    }                \
  } while(0)

void write_error() {
  int saved_errno = errno;
  puts("error");
  puts(strerror(saved_errno));
}

void timez() {
  struct timeval tv;
  CHECK(gettimeofday(&tv, NULL) == 0);
  char* time = ctime(&tv.tv_sec);
  CHECK(time != NULL);
  printf("%s", time);
}

void read_line() {
  if (fgets(line, sizeof(line), stdin) == NULL) {
    line[0] = '\0';
    return;
  }
  size_t len = strlen(line);
  if (line[len-1] == '\n') {
    line[len-1] = '\0';
  }
}

void save() {
  read_line();
  size_t len = strlen(line);
  if (len > sizeof(g_buf)-1) {
    puts("error");
    puts("too long");
  }
  memcpy(g_buf, line, len);
  g_buf[len] = '\0';
  puts("ok");
}

void sanitize_path(char* path) {
  int dots = 0;
  char* out = path;
  for (char* in = path; *in != '\0'; ++in) {
    switch(*in) {
     case '.':
      ++dots;
      break;
     case '/':
      while (dots--) {
        if (out != path) {
          --out;
        }
        while (out != path && *out != '/')
          --out;
      }
     default:
      dots = 0;
      break;
    }
    *out++ = *in;
  }
  while (dots--) {
    if (out != path) {
      --out;
    }
    while (out != path && *out != '/')
      --out;
  }
  *out = '\0';
}

void join_path(char* out, char* a, char* b) {
  out[0] = '\0';
  size_t len_a = strlen(a);
  size_t len_b = strlen(b);
  if (len_a >= PATH_MAX-1 || len_b >= PATH_MAX-len_a-1) {
    return;
  }
  memcpy(out, a, len_a);
  out[len_a] = '/';
  memcpy(out+len_a+1, b, len_b);
  out[len_a+len_b+1] = '\0';
}

void give_flag() {
  read_line();
  sanitize_path(line);
  char path[PATH_MAX];
  join_path(path, "/tmp/sboxchroot", line);
  CHECK(chdir(path) == 0);
  CHECK(chown(".", 0, 0) == 0);
  CHECK(chmod(".", 0700) == 0);
  int key_fd = open("key", O_RDONLY);
  CHECK(key_fd != -1);
  char key[sizeof(g_flag)];
  CHECK(read(key_fd, key, sizeof(key)) == sizeof(key));
  char flag[sizeof(g_flag)];
  for (int i = 0; i < sizeof(g_flag); ++i) {
    flag[i] = g_flag[i] ^ key[i];
  }
  int fd = open("flag", O_CREAT|O_EXCL|O_WRONLY, 0640);
  CHECK(fd != -1);
  CHECK(write(fd, flag, sizeof(flag)-1) == sizeof(flag)-1);
  close(fd);
  puts("ok");
}

int main(int argc, char* argv[]) {
  umask(0);
  if (prctl(PR_SET_DUMPABLE, 0)) {
    perror("prctl");
    return -1;
  }
  int fd = open("/root/flag", O_RDONLY);
  if (fd == -1) {
    perror("open");
    return -1;
  }
  if (read(fd, &g_flag, sizeof(g_flag)-1) != sizeof(g_flag)-1) {
    perror("read");
    return -1;
  }
  g_flag[sizeof(g_flag)-1] = '\0';
  close(fd);
  for (;;) {
    read_line();
    if (strcmp(line, "gimme flag") == 0) {
      give_flag();
    } else if (strcmp(line, "timez") == 0) {
      timez();
    } else if (strcmp(line, "save") == 0) {
      save();
    } else if (strcmp(line, "load") == 0) {
      puts(g_buf);
    } else if (strcmp(line, "") == 0) {
      puts("kbye");
      break;
    } else {
      puts("error");
      puts("unknown command");
    }
    fflush(stdout);
  }
  return 0;
}

