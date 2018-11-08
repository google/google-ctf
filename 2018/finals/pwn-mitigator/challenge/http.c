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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#define MAX 1024

char path[MAX] = "";
char* argv[2] = {path, 0};
int errno2http[] = {500, 403, 404, 500, 500, 500, 500, 500, 403, 500, 500, 500, 500, 403};

int *HTTP(char method[5])
{
  scanf("%4s /%[^? ]999s%", method, path);
  return method;
}

int POST(char* env[], char version[MAX])
{
  scanf("%*[^ ]%[^\n]999s", version);
  pid_t child = fork();
  if (!child) {
    execvp(argv[0], argv);
    printf("HTTP/1.0 %d Error %d\r\n\r\n", errno2http[errno], errno);
    return 0;
  }
  wait(NULL);
  return 0;
}

int GET()
{
  int fd = open(argv[0], O_RDONLY);
  char buff[MAX];
  if (fd > 0) {
    printf("HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n\r\n");
    int s;
    do {
      s = read(fd, buff, MAX);
      fwrite(buff, 1, s, stdout);
    } while(s > 0);
    close(fd);
  } else {
    printf("HTTP/1.0 404 Not Found\r\n\r\n");
  }
  return 0;
}

int main()
{
  setenv("PATH",".",1);
  char env_version[MAX] = "HTTP_VERSION=";
  char* version = &env_version[strlen(env_version)];
  char env_method[MAX] = "HTTP_METHOD=";
  char* env[] = {
    env_version,
    env_method,
    0
  };
  switch (*HTTP(&env_method[strlen(env_method)]))
  {
    case 0x544547:
      return GET();
      break;
    case 0x54534F50:
      return POST(env, &version);
      break;
    default:
      printf("HTTP/1.0 405 Method not allowed\r\n\r\n");
  }
  return 1;
}
