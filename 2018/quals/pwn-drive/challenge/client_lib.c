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

#include "client_lib.h"
#include "util.h"

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

void write_shared_file(char *filename, char *content, size_t content_len) {
  send_pid(BROKER_FD);
  send_ull(BROKER_FD, PUT_FILE);
  send_str(BROKER_FD, filename);
  send_ull(BROKER_FD, content_len);
  writen(BROKER_FD, content, content_len);
  char *resp = read_str(BROKER_FD);
  if (strcmp(resp, "OK") != 0) {
    err(1, "resp not OK");
  }
  free(resp);
}

int read_shared_file(char *filename) {
  send_pid(BROKER_FD);
  send_ull(BROKER_FD, GET_FILE);
  send_str(BROKER_FD, filename);
  send_str(BROKER_FD, filename);
  char *resp = read_str(BROKER_FD);
  if (strcmp(resp, "OK") != 0) {
    err(1, "resp not OK");
  }
  free(resp);
  open(filename, O_RDONLY);
}
