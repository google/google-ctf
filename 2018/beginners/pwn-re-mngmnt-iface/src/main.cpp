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
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

constexpr char PATCHNOTES_DIRECTORY[] = "patchnotes/";

// Flag (1): file in `pwd`. Accessible by downloading the binary and doing
// (easy) RE work or by 'guessing' the path '../flag' in the file download menu.
// flag = "CTF{I_luv_buggy_sOFtware}";
constexpr char FLAG_FILE[] = "flag";

// Flag (2): service login. Accessible via RE after the binary has been
// downloaded via /proc/self/exe.
// flag = CTF{Two_PasSworDz_Better_th4n_1_k?}
constexpr unsigned char FLAG[] = {
  132, 147, 129, 188, 147, 176, 168, 152, 151, 166, 180, 148, 176, 168, 181,
  131, 189, 152, 133, 162, 179, 179, 162, 181, 152, 179, 175, 243, 169, 152,
  246, 152, 172, 248, 186
};

void debug_shell() {
  system("/bin/sh");
}

static int cmds_executed = 0;
static bool shell_enabled = false;

void command_line() {
  char buffer[32];
  while (true) {
    printf("> ");
    // Buffer overflow.
    gets(buffer);

    cmds_executed++;
    if (!strcmp(buffer, "quit")) {
      printf("Bye!\n");
      return;
    } else if (!strcmp(buffer, "version")) {
      printf("Version 0.3\n");
    } else if (!strcmp(buffer, "shell")) {
      if (!shell_enabled) {
        printf("Security made us disable the shell, sorry!\n");
      } else {
        debug_shell();
      }
    } else if (!strncmp(buffer, "echo", 4)) {
      // Format string as well...
      printf(buffer + 5);
      printf("\n");
    } else if (!strcmp(buffer, "debug")) {
      printf("Debug data dump:\n");
      printf(" pid=%d cmds executed=%p->%d", getpid(), &cmds_executed,
             cmds_executed);
      char cmd_buffer[256];
      sprintf(cmd_buffer, "cat /proc/%d/maps", getpid());
      printf(" Mappings:\n");
      system(cmd_buffer);
    } else {
      printf("Unknown command '%s'\n", buffer);
    }
  }
}

void secondary_login() {
  char password[128];
  printf("! Two factor authentication required !\n");
  printf("Please enter secret secondary password:\n");
  scanf("%127s", password);
  size_t l = strlen(password);
  for (size_t i = 0; i < l; i++) {
    password[i] ^= 0xC7;
  }

  // Unintended bug: memcpy instead of memcmp, woops!
  if (l == sizeof(FLAG) && memcpy(password, FLAG, sizeof(FLAG))) {
    printf("Authenticated\n");
    command_line();
  } else {
    printf("Access denied.\n");
    exit(1);
  }
}

void primary_login() {
  printf("Please enter the backdoo^Wservice password:\n");
  int fd = open(FLAG_FILE, O_RDONLY);
  char buf[128] = {};
  if (fd == -1) {
    printf("Login mechanism corrupted!\n");
    exit(1);
  } else {
    read(fd, buf, sizeof(buf) - 1);
    close(fd);
    char buf2[128];
    scanf("%127s", buf2);
    if (!strcmp(buf2, buf)) {
      secondary_login();
    } else {
      printf("Incorrect, the authorities have been informed!\n");
      exit(1);
    }
  }
}

int main(int argc, char *argv[]) {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  while (true) {
    printf("=== Management Interface ===\n");
    printf(" 1) Service access\n");
    printf(" 2) Read EULA/patch notes\n");
    printf(" 3) Quit\n");

    int choice;
    while (scanf("%d", &choice) != 1 || choice < 1 || choice > 3) {
      printf("Invalid choice\n");

      // Clear input buffer.
      bool flushed = false;
      while (!flushed) {
        switch (getchar()) {
          case '\n':
          case EOF:
            flushed = true;
            break;
          default:
            break;
        }
      }
    }

    switch (choice) {
      case 1: {
        primary_login();
      } break;
      case 2: {
        // Patchnotes - aka arbitrary file download.
        char buffer[256 + sizeof(PATCHNOTES_DIRECTORY)];
        strncpy(buffer, PATCHNOTES_DIRECTORY, sizeof(buffer));
        DIR *dir = opendir(PATCHNOTES_DIRECTORY);
        if (!dir) {
          printf("No patchnotes found!\n");
        } else {
          printf("The following patchnotes were found:\n");
          struct dirent *current;
          struct stat fstats;
          while ((current = readdir(dir))) {
            strncpy(
              buffer + sizeof(PATCHNOTES_DIRECTORY) - 1,
              current->d_name,
              sizeof(buffer) - sizeof(PATCHNOTES_DIRECTORY));
            if (stat(buffer, &fstats) == -1) {
              // Stat failed.
              printf(" - stat failed for %s\n", buffer);
              continue;
            }
            if (!(fstats.st_mode & S_IFREG)) {
              // Only show regular files.
              continue;
            }
            printf(" - %s\n", current->d_name);
          }
          closedir(dir);
        }

        printf("Which patchnotes should be shown?\n");
        scanf("%255s", buffer + sizeof(PATCHNOTES_DIRECTORY) - 1);

        // Try to open the file.
        int fd = open(buffer, O_RDONLY);
        if (fd == -1) {
          printf("Error: %s\n", strerror(errno));
        } else {
          ssize_t c;
          while ((c = read(fd, buffer, sizeof(buffer))) > 0) {
            write(1, buffer, c);
          }
          close(fd);
        }
      } break;
      case 3: {
        return 0;
      }
    }
    fflush(nullptr);
  }
}

