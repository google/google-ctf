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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MOTD_LEN 256
char MOTD[MOTD_LEN];
char *DEFAULT_MOTD = "MOTD: Welcome back friend!";

void set_motd(){
  char buf[MOTD_LEN];

  printf("Enter new message of the day\n");
  printf("New msg: ");

  // Uh oh!
  gets(buf);

  strncpy(MOTD, buf, MOTD_LEN);
  MOTD[MOTD_LEN - 1] = '\0';

  printf("New message of the day saved!\n");
  return;
}

void get_motd(){
  printf(MOTD);
  printf("\n");
  return;
}

void set_admin_motd(){
  printf("TODO: Allow admin MOTD to be set\n");
  return;
}
void read_flag();

void get_admin_motd(){
  uid_t uid = getuid();
  if(uid != 0) {
    printf("You're not root!\n");
  }
  else {
    read_flag();
  }
  return;
}

void print_menu(){
  printf("Choose functionality to test:\n");
  printf("1 - Get user MOTD\n");
  printf("2 - Set user MOTD\n");
  printf("3 - Set admin MOTD (TODO)\n");
  printf("4 - Get admin MOTD\n");
  printf("5 - Exit\n");
}

int main(int argc, char* argv[]){
  void *cmd;
  char *input;
  size_t input_len;
  int choice, nitems = 0;

  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  fflush(stdin);
  strcpy(MOTD, DEFAULT_MOTD);
  while(choice != 5){
    print_menu();
    printf("choice: ");

    getline(&input, &input_len, stdin);
    choice = atoi(input);
    if(choice == 0){
      printf("Unrecognized input!\n");
      continue;
    }
    else if (choice < 1 || choice > 5){
      printf("Not an option!\n");
      continue;
    }
    else {
      switch (choice){
        case 1:
          get_motd();
          break;
        case 2:
          set_motd();
          break;
        case 3:
          set_admin_motd();
          break;
        case 4:
          get_admin_motd();
          break;
        case 5:
          return 0;
      }
    }
  }
}



void read_flag(){
  FILE *fd;
  char flag[256] = {0};
  fd = fopen("./flag.txt", "r");
  fscanf(fd,"%s", &flag);

  printf("Admin MOTD is: %s\n", flag);
  return;
}
