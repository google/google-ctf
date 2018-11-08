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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <ctype.h>
#include <linux/limits.h>

const char BANNER[] = "\
███████╗███╗   ███╗ █████╗ ██████╗ ████████╗    ███████╗██████╗ ██╗██████╗  ██████╗ ███████╗    ██████╗  ██████╗  ██████╗  ██████╗        \n\
██╔════╝████╗ ████║██╔══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝    ╚════██╗██╔═████╗██╔═████╗██╔═████╗       \n\
███████╗██╔████╔██║███████║██████╔╝   ██║       █████╗  ██████╔╝██║██║  ██║██║  ███╗█████╗       █████╔╝██║██╔██║██║██╔██║██║██╔██║       \n\
╚════██║██║╚██╔╝██║██╔══██║██╔══██╗   ██║       ██╔══╝  ██╔══██╗██║██║  ██║██║   ██║██╔══╝      ██╔═══╝ ████╔╝██║████╔╝██║████╔╝██║       \n\
███████║██║ ╚═╝ ██║██║  ██║██║  ██║   ██║       ██║     ██║  ██║██║██████╔╝╚██████╔╝███████╗    ███████╗╚██████╔╝╚██████╔╝╚██████╔╝       \n\
╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝       ╚═╝     ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝    ╚══════╝ ╚═════╝  ╚═════╝  ╚═════╝        \n\
                                                                                                                                          \n\
 █████╗ ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗███████╗██████╗     ████████╗ ██████╗ ██████╗  ██████╗     ██╗     ██╗███████╗████████╗\n\
██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗    ╚══██╔══╝██╔═══██╗██╔══██╗██╔═══██╗    ██║     ██║██╔════╝╚══██╔══╝\n\
███████║██║  ██║██║   ██║███████║██╔██╗ ██║██║     █████╗  ██║  ██║       ██║   ██║   ██║██║  ██║██║   ██║    ██║     ██║███████╗   ██║   \n\
██╔══██║██║  ██║╚██╗ ██╔╝██╔══██║██║╚██╗██║██║     ██╔══╝  ██║  ██║       ██║   ██║   ██║██║  ██║██║   ██║    ██║     ██║╚════██║   ██║   \n\
██║  ██║██████╔╝ ╚████╔╝ ██║  ██║██║ ╚████║╚██████╗███████╗██████╔╝       ██║   ╚██████╔╝██████╔╝╚██████╔╝    ███████╗██║███████║   ██║   \n\
╚═╝  ╚═╝╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═════╝        ╚═╝    ╚═════╝ ╚═════╝  ╚═════╝     ╚══════╝╚═╝╚══════╝   ╚═╝   ";

const char MENU[] = "\n\
Hi %s, what would you like to do?\n\
1) Print TODO list\n\
2) Print TODO entry\n\
3) Store TODO entry\n\
4) Delete TODO entry\n\
5) Remote administration\n\
6) Exit\n\
> ";
const char OUT_OF_BOUNDS_MESSAGE[] = "Sorry but this model only supports 128 TODO list entries.\nPlease upgrade to the Smart Fridge 3001 for increased capacity.";

#define TODO_COUNT 128
#define TODO_LENGTH 48

int todo_fd;
char username[64];
char todos[TODO_COUNT*TODO_LENGTH];

void init() {
  system("mkdir todos 2>/dev/null");
  setlinebuf(stdout);
}

void read_line(char *buf, size_t buf_sz) {
  if (!fgets(buf, buf_sz, stdin)) {
    err(1, "fgets()");
  }
  size_t read_cnt = strlen(buf);
  if (read_cnt && buf[read_cnt-1] == '\n') {
    buf[read_cnt-1] = 0;
  }
}

bool read_all(int fd, char *buf, size_t read_sz) {
  while (read_sz) {
    ssize_t num_read = read(fd, buf, read_sz);
    if (num_read <= 0) {
      return false;
    }
    read_sz -= num_read;
    buf += num_read;
  }
  return true;
}

void write_all(int fd, char *buf, size_t write_sz) {
  while (write_sz) {
    ssize_t num_written = write(fd, buf, write_sz);
    if (num_written <= 0) {
      err(1, "write");
    }
    write_sz -= num_written;
    buf += num_written;
  }
}

bool string_is_alpha(const char *s) {
  for (; *s; s++) {
    if (!isalpha(*s)) {
      return false;
    }
  }
  return true;
}

bool list_is_empty() {
  for (int i = 0; i < TODO_COUNT; i++) {
    if(todos[i*TODO_LENGTH]) {
      return false;
    }
  }
  return true;
}

void print_list() {
  if (list_is_empty()) {
    puts("Your TODO list is empty. Enjoy your free time!");
    return;
  }
  puts("+=====+=================================================================+");
  for (int i = 0; i < TODO_COUNT; i++) {
    if(todos[i*TODO_LENGTH]) {
      printf("| %3d | %-63s |\n", i, &todos[i*TODO_LENGTH]);
    }
  }
  puts("+=====+=================================================================+");
}

void open_todos() {
  char todos_filename[PATH_MAX] = "todos/";
  strncat(todos_filename, username, sizeof(todos_filename)-strlen(todos_filename) - 1);

  todo_fd = open(todos_filename, O_RDWR);
  if (todo_fd != -1 && read_all(todo_fd, todos, sizeof(todos))) {
    if (!list_is_empty()) {
      print_list();
    }
  } else {
    todo_fd = open(todos_filename, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (todo_fd == -1) {
      err(1, "Could not create TODO storage file");
    }
  }
}

void authenticate() {
  printf("user: ");
  fflush(stdout);
  read_line(username, sizeof(username));

  if (!string_is_alpha(username)) {
    errx(1, "username can only consist of [a-zA-Z]");
  }
}

int read_int() {
  char buf[128];
  read_line(buf, sizeof(buf));
  return atoi(buf);
}

void store_todos() {
  write_all(todo_fd, todos, sizeof(todos));
  close(todo_fd);
}

void store_todo() {
  printf("In which slot would you like to store the new entry? ");
  fflush(stdout);
  int idx = read_int();
  if (idx > TODO_COUNT) {
    puts(OUT_OF_BOUNDS_MESSAGE);
    return;
  }
  printf("What's your TODO? ");
  fflush(stdout);
  read_line(&todos[idx*TODO_LENGTH], TODO_LENGTH);
}

void print_todo() {
  printf("Which entry would you like to read? ");
  fflush(stdout);
  int idx = read_int();
  if (idx > TODO_COUNT) {
    puts(OUT_OF_BOUNDS_MESSAGE);
    return;
  }
  printf("Your TODO: %s\n", &todos[idx*TODO_LENGTH]);
}

void delete_todo() {
  printf("Which TODO number did you finish? ");
  fflush(stdout);
  int idx = read_int();
  if (idx > TODO_COUNT) {
    puts(OUT_OF_BOUNDS_MESSAGE);
    return;
  }
  todos[idx*TODO_LENGTH] = 0;
  if (list_is_empty()) {
    puts("Awesome, you cleared the whole list!");
  } else {
    puts("Nice job, keep it up!");
  }
}

bool administration_enabled() {
  return false;
}

void admin() {
  puts("Sorry, remote administration is not available right now.");
}

int main(int argc, char *argv[]) {
  init();

  puts(BANNER);

  authenticate();

  open_todos();

  while (true) {
    printf(MENU, username);
    fflush(stdout);
    int choice = read_int();
    puts("");
    switch (choice) {
      case 1:
        print_list();
        break;
      case 2:
        print_todo();
        break;
      case 3:
        store_todo();
        break;
      case 4:
        delete_todo();
        break;
      case 5:
        admin();
        break;
      case 6:
        store_todos();
        puts("Your TODO list has been stored. Have a nice day!");
        return 0;
      default:
        printf("unknown option %d\n", choice);
        break;
    }
  }
}
