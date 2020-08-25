/*
 * Copyright 2020 Google LLC
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

#include "../gatekey/gatekey_api.h"
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <stdio.h>

int read_until_terminator(int fd, const char *name, char *buf, char terminator) {
  int len = 0;
  while (1) {
    int res = read(fd, buf+len, 1);
    if (res != 1) {
      if (res == 0)
        errx(1, "read %s: EOF", name);
      else
        err(1, "read %s", name);
    }
    if (buf[len] == '\n') {
      buf[len] = '\0';
      return len;
    }
    len++;
  }
}

int read_string(const char *name, char *buf) {
  printf("%s> ", name);
  return read_until_terminator(0, name, buf, '\n');
}

void handle_database_commands(int dbfd) {
  char buf[1000];
  unsigned long pos = 16;
  while (1) {
    puts("Available commands:");
    puts("  (c)lose database");
    puts("  (s)how next record (there must be a following record for this)");
    puts("  (a)ppend record");
    puts("  (r)ewind back to first record");
    char cmd[2];
    read_string("db", cmd);
    switch (cmd[0]) {
    case 'c':
      return;
    case 's':;
      /* read one entry (until newline) */
      char entry[1000] = {0};
      int len = pread(dbfd, entry, sizeof(entry), pos);
      if (len == -1) err(1, "read entry");
      if (len == 0) {
        puts("EOF");
        break;
      }
      char *entry_end = memchr(entry, '\n', len);
      if (entry_end)
        len = (entry_end + 1) - entry;
      pos += len; /* next read should start at next record, not at end of the area we read */
      write(1, entry, len);
      break;
    case 'a':
      /* skip to the end */
      while (1) {
        char c;
        int res = pread(dbfd, &c, 1, pos);
        if (res == 0) break;
        if (res == -1) err(1, "unable to skip to end of db file");
        pos++;
      }

      int buf_len = read_string("new data", buf);
      if (pwrite(dbfd, buf, buf_len, pos) != buf_len)
        err(1, "failed to append db record");
      pos += buf_len;
      if (pwrite(dbfd, "\n", 1, pos) != 1)
        err(1, "failed to terminate db record");
      pos++;
      break;
    case 'r':
      pos = 16;
      break;
    default:
      puts("unknown command");
      break;
    }
  }
}

int main(void) {
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  gatekey_setup();
  puts("gatekey started up");

  while (1) {
    puts("Available commands:");
    puts("  (q)uit\n");
    puts("  (o)pen database");
    puts("  (c)reate database");
    printf("> ");
    char cmd[2];
    int cmd_read_res = read(0, cmd, 2);
    if (cmd_read_res != 2) {
      if (cmd_read_res == -1)
        err(1, "can't read cmd");
      else
        errx(1, "short/EOF cmd");
    }

    switch (cmd[0]) {
    case 'q':
      return 0;
    case 'o': {
      char dbname[100], key[65];
      read_string("dbname", dbname);
      read_string("key", key);
      int dbfd = gatekey_open(dbname, key);
      if (dbfd < 0) {
        printf("failed to open database: %s\n", strerror(-dbfd));
      } else {
        handle_database_commands(dbfd);
        close(dbfd);
      }
      break;
    }
    case 'c': {
      char dbname[100], key[65];
      read_string("dbname", dbname);
      int dbfd = gatekey_create(dbname, key);
      key[64] = '\0';
      if (dbfd < 0) {
        printf("failed to create database: %s\n", strerror(-dbfd));
      } else {
        printf("database created successfully with key '%s'\n", key);
        handle_database_commands(dbfd);
        close(dbfd);
      }
      break;
    }
    default:
      printf("unknown command '%c'\n", cmd[0]);
      break;
    }
  }
}