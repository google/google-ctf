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



#include <stdio.h>
#include <stdlib.h>

#define MAX_NODES     1000
#define MAX_REG       26

#define INC           0
#define DECJMP        1
#define FRA           2

#define LAST_INSTRUCTION FRA

typedef unsigned char byte;
typedef struct frame *Frame;
typedef unsigned long long ull;


// A program will have a single int arg, loaded in register 0.
// It starts on node 0, and if it reaches node numNodes, it will halt.
// What is in node 0 will get printed out.
struct program {
  unsigned int numNodes;
  struct node* nodes;
};

struct incIns {
  byte r;
  unsigned int next;
};

struct decJmpIns {
  byte r;
  unsigned int nextNonZ;
  unsigned int nextZ;
};

struct fraIns {
  // This is the amount of nodes to save when coming back from the new frame.
  unsigned int amo;
  // This is the node to jump to for the new frame.
  unsigned int frameNext;
  unsigned int next;
};

union inst {
  struct incIns inc;
  struct decJmpIns decJmp;
  struct fraIns fra;
};

struct node {
  unsigned int type;
  union inst ins;
};

struct frame {
  ull regs[MAX_REG];
};

struct program program;

Frame getNewFrame() {
  Frame f = malloc(sizeof (struct frame));
  int i;
  for (i = 0; i < MAX_REG; i++) {
    f->regs[i] = 0;
  }
  return f;
}

Frame copyFrame(Frame f) {
  Frame newF = malloc(sizeof (struct frame));
  int i;
  for (i = 0; i < MAX_REG; i++) {
    newF->regs[i] = f->regs[i];
  }
  return newF;
}

void freeFrame(Frame f) {
  free(f);
}

void runProgram(Frame f, int startNode) {
  int at = startNode;
  while (at != program.numNodes) {
    struct node *n = &program.nodes[at];
    if (n->type == INC) {
      struct incIns *ins = &n->ins.inc;
      f->regs[ins->r]++;
      at = ins->next;
    } else if (n->type == DECJMP) {
      struct decJmpIns *ins = &n->ins.decJmp;
      if (f->regs[ins->r] == 0) {
        at = ins->nextZ;
      } else {
        f->regs[ins->r]--;
        at = ins->nextNonZ;
      }
    } else if (n->type == FRA) {
      struct fraIns *ins = &n->ins.fra;
      Frame newF = copyFrame(f);
      runProgram(newF, ins->frameNext);
      int i;
      for (i = 0; i < ins->amo; i++) {
        f->regs[i] = newF->regs[i];
      }
      freeFrame(newF);
      at = ins->next;
    }
  }
}

void readCode() {
  FILE *f = fopen("code", "rb");
  if (f == NULL) {
    printf ("Could not find file\n");
    exit(1);
  }
  int nodes;
  if (fread(&nodes, 4, 1, f) != 1) {
    printf("Error reading file\n");
    exit(1);
  }
  if (nodes <= 0 || nodes > MAX_NODES) {
    printf("Invalid number\n");
    exit(1);
  }
  program.nodes = malloc(sizeof (struct node) * nodes);
  program.numNodes = nodes;
  int i;
  for (i = 0; i < nodes; i++) {
    if (fread(&program.nodes[i], sizeof (struct node), 1, f) != 1) {
      printf("Error reading file\n");
      exit(1);
    }
    // Validate.
    if (program.nodes[i].type == INC) {
      struct incIns *ins = &program.nodes[i].ins.inc;
      if (ins->r >= MAX_REG) {
        printf("Invalid reg\n");
        exit(1);
      }
      if (ins->next > nodes) {
        printf("Invalid next\n");
        exit(1);
      }
    } else if (program.nodes[i].type == DECJMP) {
      struct decJmpIns *ins = &program.nodes[i].ins.decJmp;
      if (ins->r >= MAX_REG) {
        printf("Invalid reg\n");
        exit(1);
      }
      if (ins->nextNonZ > nodes) {
        printf("Invalid next\n");
        exit(1);
      }
      if (ins->nextZ > nodes) {
        printf("Invalid next\n");
        exit(1);
      }
    } else if (program.nodes[i].type == FRA) {
      struct fraIns *ins = &program.nodes[i].ins.fra;
      if (ins->amo > MAX_REG) {
        printf("Invalid amo\n");
        exit(1);
      }
      if (ins->frameNext > nodes) {
        printf("Invalid next\n");
        exit(1);
      }
      if (ins->next > nodes) {
        printf("Invalid next\n");
        exit(1);
      }
    } else {
      printf("Invalid ins\n");
      exit(1);
    }
  }
  fclose(f);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Need one argument\n");
    return 1;
  }
  int s = atoi(argv[1]);
  readCode();
  Frame f = getNewFrame();
  f->regs[0] = s;
  runProgram(f, 0);
  printf ("CTF{%016llx}\n", f->regs[0]);
  freeFrame(f);
  return 0;
}
