/**
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * bufferflow triggering segfault  - binary, compile with:
 * gcc /tmp/console.c -o /tmp/console -static -s
 *
 * Console allows the player to test run the binary (bof).
 * Crashing bof will trigger the 1st flag.
 * Controlling the buffer overflow in bof will trigger the 2nd flag.
 */

int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  char inputs[256];
  printf("Your goal: try to crash the Cauliflower system by providing input to the program which is launched by using 'run' command.\n Bonus flag for controlling the crash.\n");
  while(1) {
    printf("\nConsole commands: \nrun\nquit\n>>");
    if (fgets(inputs, 256, stdin) == NULL) {
      exit(0);
    }
    printf("Inputs: %s", inputs);
    if ( strncmp(inputs, "run\n\0", 256) == 0 ) {
      int result = system("/usr/bin/qemu-mipsel-static ./bof");
      continue;
    } else if ( strncmp(inputs, "quit\n\0", 256) == 0 ) {
      exit(0);
    } else {
      puts("Unable to determine action from your input");
      exit(0);
    }
  }
  return 0;
}
