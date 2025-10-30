/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void intro(void) {
  puts("Welcome to Playbook Manager 2000!");
}

void manual(void) {
  // Gemini said that :)
  puts("");
  puts("PM2000 is a mission-critical, enterprise-grade solution empowering");
  puts("stakeholders to seamlessly manage and execute standardized operational");
  puts("protocols - or \"synergistic action matrices\" - across the entire");
  puts("digital ecosystem.");
  puts("");
  puts("The system's core value proposition lies in its ability to transform");
  puts("reactive firefighting into a proactive, metrics-driven discipline.");
  puts("By codifying institutional knowledge into repeatable \"success");
  puts("blueprints,\" PM2000 minimizes human error, accelerates time-to-resolution,");
  puts("and ultimately optimizes resource allocation.");
  puts("");
  puts("Traditionally, playbooks are just lists of steps:");
  puts("");
  puts("Daily routine.");
  puts("1. Check time");
  puts("  a. `date`");
  puts("  b. Double check");
  puts("  c. `sleep 1`");
  puts("  d. `date`");
  puts("2. List files");
  puts("  a. `ls`");
  puts("");
  // Gemini again!
  puts("PM2000 introduces Standardized Operational Procedure Syntax (SOPS).");
  puts("SOPS leverages a highly formalized, yet remarkably intuitive, \"protocol");
  puts("specification grammar,\" enabling stakeholders to define sequential");
  puts("execution pathways with unparalleled clarity. Each \"actionable directive\"");
  puts("within a SOPS playbook is expressed through a standardized nomenclature,");
  puts("ensuring unambiguous interpretation and seamless execution by the underlying");
  puts("PM2000 engine. The legacy playbook would be translated into SOPS as follows:");
  puts("");
  puts("note: Daily routine");
  puts("STEP");
  puts("  note: Check time");
  puts("  STEP");
  puts("    cmd: date");
  puts("  ENDSTEP");
  puts("  STEP");
  puts("    note: Double check");
  puts("  ENDSTEP");
  puts("  STEP");
  puts("    cmd: sleep 1");
  puts("  ENDSTEP");
  puts("  STEP");
  puts("    cmd: date");
  puts("  ENDSTEP");
  puts("ENDSTEP");
  puts("STEP");
  puts("  note: List files");
  puts("  STEP");
  puts("    cmd: ls");
  puts("  ENDSTEP");
  puts("ENDSTEP");
  puts("");
}

#define MAX_CHILDREN 10
#define MAX_BUF_SIZE 512
#define MAX_STEP_COUNT 1024
#define MAX_NESTING_DEPTH 10

// Must be smaller than BUF_SIZE.
#define MAX_LINE 256

#define FLAG_ALLOCATED 1
#define FLAG_CMD       2
#define FLAG_NOTE      4

typedef struct {
  int type;
  int children[MAX_CHILDREN];
  char buf[MAX_BUF_SIZE];
} step;

step steps[MAX_STEP_COUNT];

int allocate_playbook(void) {
  // Skipping the first one - then zeroed children are invalid.
  for (int i = 1; i < MAX_STEP_COUNT; i++) {
    if (!(steps[i].type & FLAG_ALLOCATED)) {
      memset(steps + i, 0, sizeof(step));
      // No type otherwise.
      steps[i].type = FLAG_ALLOCATED;
      return i;
    }
  }
  puts("Out of memory.");
  exit(1);
}

void add_child(int a, int b) {
  for (int i = 0; i < MAX_CHILDREN; i++) {
    if (steps[a].children[i] == 0) {
      steps[a].children[i] = b;
      return;
    }
  }
  puts("Max fanout reached.");
  exit(1);
}

void validate_command(const char* command) {
  if (!strcmp(command, "date")) { return; }
  if (!strcmp(command, "sleep 1")) { return; }
  if (!strcmp(command, "ls")) { return; }
  puts("Blocking potentially dangerous command. Contact our sales department if you need whitelist updates.");
  exit(1);
}


void skip() {
  char line[MAX_LINE] = {0};
  fgets(line, MAX_LINE-5, stdin);
}

int nesting_depth = 0;

void new_playbook(void) {
  struct{
    char line[MAX_LINE*8];
    char word[MAX_LINE*8];
    volatile int soft_buf_limit;
    int stack[MAX_NESTING_DEPTH];
    int* sp;
    int just_new_step;
  } s;

  s.sp = s.stack;
  s.just_new_step = 1;
  s.soft_buf_limit = MAX_LINE-5;
  puts("Enter new playbook in the SOPS language. Empty line finishes the entry.");
  s.stack[0] = allocate_playbook();
  while (fgets(s.line, s.soft_buf_limit, stdin)) {
    //printf("TODO: DEBUG: got [%s] at len %d\n", s.line, s.soft_buf_limit);
    if (s.line[0] == '\n') break;
    memset(s.word, 0, sizeof(s.word));
    sscanf(s.line, "%s", s.word);
    if (!strcmp(s.word, "STEP")) {
      s.sp += 1;
      nesting_depth += 1;
      if (nesting_depth >= MAX_NESTING_DEPTH) {
        puts("Max nesting depth reached.");
        exit(1);
      }
      *s.sp = allocate_playbook();
      add_child(s.sp[-1], *s.sp);
      s.just_new_step = 1;
      continue;
    }
    else if (!strcmp(s.word, "ENDSTEP")) {
      s.sp -= 1;
      nesting_depth -= 1;
      if (nesting_depth < 0) {
        puts("Mismatched STEP and ENDSTEP.");
        exit(1);
      }
    }
    else if (!strcmp(s.word, "cmd:")) {
      if (!s.just_new_step) {
        puts("Note and command statements are allowed only immediately after STEP statements.");
        exit(1);
      }
      sscanf(s.line, "%s %[^\n]", s.word, s.word);
      validate_command(s.word);
      strcpy(steps[*s.sp].buf, s.word);
      steps[*s.sp].type |= FLAG_CMD;
    }
    else if (!strcmp(s.word, "note:")) {
      if (!s.just_new_step) {
        puts("Note and command statements are allowed only immediately after STEP statements.");
        exit(1);
      }
      sscanf(s.line, "%s %[^\n]", s.word, s.word);
      strcpy(steps[*s.sp].buf, s.word);
      steps[*s.sp].type |= FLAG_NOTE;
    }
    else {
      puts("Invalid statement.");
      exit(1);
    }
    s.just_new_step = 0;
  }
  printf("Saved playbook (id %d).\n\n", s.stack[0]);
}

int get_int() {
  char line[MAX_LINE] = {0};
  while (1) {
    fgets(line, MAX_LINE-5, stdin);
    int num;
    if (sscanf(line, "%d", &num) == 1) {
      return num;
    }
  }
}

void delete_recursive(int id) {
  if (id < 1 || id >= MAX_STEP_COUNT) {
    printf("Invalid id.\n");
    exit(1);
  }

  if (!(steps[id].type & FLAG_ALLOCATED)) {
    printf("This playbook does not exist.\n");
    return;
  }

  steps[id].type = 0;

  for (int i = 0; i < MAX_CHILDREN; i++) {
    if (steps[id].children[i]) {
      delete_recursive(steps[id].children[i]);
    }
  }
}

void delete_playbook(void) {
  printf("Enter playbook id:\n");
  int id = get_int();
  delete_recursive(id);
}

void print_depth(int depth) {
  for (int i = 0; i < depth; i++) {
    printf(" ");
  }
}

void execute(int id, int depth) {
  if (id < 1 || id >= MAX_STEP_COUNT) {
    printf("Invalid id.\n");
    exit(1);
  }

  if (!(steps[id].type & FLAG_ALLOCATED)) {
    printf("This playbook does not exist.\n");
    return;
  }

  if (steps[id].type & FLAG_CMD) {
    print_depth(depth);
    printf("Command: %s\n", steps[id].buf);
    skip();
    system(steps[id].buf);
    skip();
  }
  else if (steps[id].type & FLAG_NOTE) {
    print_depth(depth);
    printf("Note: %s\n", steps[id].buf);
    skip();
  }

  for (int i = 0; i < MAX_CHILDREN; i++) {
    if (steps[id].children[i]) {
      execute(steps[id].children[i], depth+1);
    }
  }
}

void run_playbook(void) {
  printf("Enter playbook id:\n");
  int id = get_int();
  printf("Executing playbook %d. Press enter to complete the step.\n", id);
  execute(id, 0);
}

/*
void debug() {
  for (int i = 0; i < 10; i++) {
    printf("%d.\n", i);
    printf("Type: %d\n", steps[i].type);
    printf("Children:");
    for (int j = 0; j < MAX_CHILDREN; j++) {
      printf(" %d", steps[i].children[j]);
    }
    printf("\nBuf: [%s]\n\n", steps[i].buf);
  }
}
*/

void menu(void) {
  puts("=== MENU ===");
  puts("1. Manual");
  puts("2. New playbook");
  puts("3. Delete playbook");
  puts("4. Run playbook");
  puts("5. Quit");
  int option = get_int();
  switch (option) {
  case 1: manual(); break;
  case 2: new_playbook(); break;
  case 3: delete_playbook(); break;
  case 4: run_playbook(); break;
  case 5: exit(0); break;
  //case 1337: debug(); break;
  }
}

int main(int argc, char *argv[]) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  intro();
  while (1) {
    menu();
  }
}
