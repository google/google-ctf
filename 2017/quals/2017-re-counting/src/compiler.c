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
#include <string.h>

#define INC           0
#define DECJMP        1
#define FRA           2

typedef unsigned char byte;

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

typedef struct mapNode *MapNode;

struct mapNode {
  MapNode next[27];
  int hasOne;
};

int numLines;
char lines[1000][100];

int firstNode[1000];
char unres[1000][100];

int upTo;
struct node outputNodes[100000];

MapNode rootNode;

int beginsWith(char *line, char *str) {
  return strncmp(line, str, strlen(str)) == 0;
}

MapNode newMapNode() {
  MapNode n = malloc(sizeof (struct mapNode));
  int i;
  for (i = 0; i < 27; i++) {
    n->next[i] = NULL;
  }
  n->hasOne = -1;
  return n;
}

void addToMap(int at) {
  MapNode cur = rootNode;
  char *name = &lines[at][1];
  int i;
  for (i = 0; (name[i] >= 'a' && name[i] <= 'z') || name[i] == '_'; i++) {
    int v = name[i] - 'a';
    if (name[i] == '_') {
      v = 26;
    }
    if (cur->next[v] == NULL) {
      cur->next[v] = newMapNode();
    }
    cur = cur->next[v];
  }
  if (cur->hasOne != -1) {
    printf ("Multiple defined names: %d\n", at);
    return;
  }
  cur->hasOne = at;
}

int getName(char *name) {
  MapNode at = rootNode;
  int i;
  for (i = 0; (name[i] >= 'a' && name[i] <= 'z') || name[i] == '_'; i++) {
    int v = name[i] - 'a';
    if (name[i] == '_') {
      v = 26;
    }
    if (at->next[v] == NULL) {
      return -1;
    }
    at = at->next[v];
  }
  return at->hasOne;
}

void addInc(int at) {
  char *line = lines[at];
  char r;
  if (sscanf (line, "inc %c ", &r) != 1) {
    printf("Could not parse inc: %d\n", at);
    return;
  }
  if (r < 'a' || r > 'z') {
    printf ("Invalid reg %d\n", at);
    return;
  }
  firstNode[at] = upTo;
  struct node *n = &outputNodes[upTo++];
  n->type = INC;
  n->ins.inc.r = r - 'a';
}

void addDecJmp(int at) {
  char *line = lines[at];
  char r;
  if (sscanf (line, "decjmp %c %s ", &r, unres[at]) != 2) {
    printf("Could not parse decjmp: %d\n", at);
    return;
  }
  if (r < 'a' || r > 'z') {
    printf ("Invalid reg %d\n", at);
    return;
  }
  firstNode[at] = upTo;
  struct node *n = &outputNodes[upTo++];
  n->type = DECJMP;
  n->ins.decJmp.r = r - 'a';
}

void addCall(int at) {
  char *line = lines[at];
  int numS;
  if (sscanf (line, "call %d %s ", &numS, unres[at]) != 2) {
    printf("Could not parse call: %d\n", at);
    return;
  }
  if (numS < 0 || numS > 26) {
    printf ("Invalid num sav %d\n", at);
    return;
  }
  firstNode[at] = upTo;
  struct node *n = &outputNodes[upTo++];
  n->type = FRA;
  n->ins.fra.amo = numS;
}

void addRet(int at) {
  firstNode[at] = -1;
}

void addClr(int at) {
  char *line = lines[at];
  char r;
  if (sscanf (line, "clr %c ", &r) != 1) {
    printf("Could not parse clr: %d\n", at);
    return;
  }
  if (r < 'a' || r > 'z') {
    printf ("Invalid reg %d\n", at);
    return;
  }
  firstNode[at] = upTo;
  struct node *n = &outputNodes[upTo++];
  n->type = DECJMP;
  n->ins.decJmp.r = r - 'a';
  n->ins.decJmp.nextNonZ = firstNode[at];
}

void addJmp(int at) {
  char *line = lines[at];
  if (sscanf (line, "jmp %s ", unres[at]) != 1) {
    printf("Could not parse jmp: %d\n", at);
    return;
  }
  firstNode[at] = upTo;
  struct node *n = &outputNodes[upTo++];
  n->type = DECJMP;
  n->ins.decJmp.r = 25;
  n->ins.decJmp.nextNonZ = 0;
}

void addAdd(int at) {
  char *line = lines[at];
  char r1;
  char r2;
  if (sscanf (line, "add %c %c ", &r1, &r2) != 2) {
    printf("Could not parse add: %d\n", at);
    return;
  }
  if (r1 < 'a' || r1 > 'z' || r2 < 'a' || r2 > 'z') {
    printf ("Invalid reg %d\n", at);
    return;
  }
  firstNode[at] = upTo;
  struct node *n1 = &outputNodes[upTo++];
  struct node *n2 = &outputNodes[upTo++];
  n1->type = DECJMP;
  n1->ins.decJmp.r = r2 - 'a';
  n1->ins.decJmp.nextNonZ = firstNode[at] + 1;

  n2->type = INC;
  n2->ins.inc.r = r1 - 'a';
  n2->ins.inc.next = firstNode[at];
}

void fillInLine(int at) {
  char *line = lines[at];
  if (line[0] == ':') {
    addToMap(at);
    firstNode[at] = -2;
    return;
  }
  if (line[0] == '#') {
    firstNode[at] = -2;
    return;
  }
  if (beginsWith(line, "inc")) {
    addInc(at);
  } else if (beginsWith(line, "decjmp")) {
    addDecJmp(at);
  } else if (beginsWith(line, "call")) {
    addCall(at);
  } else if (beginsWith(line, "ret")) {
    addRet(at);
  } else if (beginsWith(line, "clr")) {
    addClr(at);
  } else if (beginsWith(line, "jmp")) {
    addJmp(at);
  } else if (beginsWith(line, "add")) {
    addAdd(at);
  } else {
    printf ("Unknown line: %d\n", at);
    return;
  }
}

void fixUpLine(int at) {
  char *line = lines[at];
  if (line[0] == ':' || line[0] == '#') {
    return;
  }
  int goTo = firstNode[at + 1];
  if (goTo == -1) {
    goTo = upTo;
  }
  if (beginsWith(line, "inc")) {
    outputNodes[firstNode[at]].ins.inc.next = goTo;
  } else if (beginsWith(line, "decjmp")) {
    int bit = getName(unres[at]);
    if (bit == -1) {
      printf ("Could not resolve name for %d\n", at);
      return;
    }
    bit = firstNode[bit];
    if (bit == -1) {
      bit = upTo;
    }
    outputNodes[firstNode[at]].ins.decJmp.nextZ = bit;
    outputNodes[firstNode[at]].ins.decJmp.nextNonZ = goTo;
  } else if (beginsWith(line, "call")) {
    int bit = getName(unres[at]);
    if (bit == -1) {
      printf ("Could not resolve name for %d\n", at);
      return;
    }
    bit = firstNode[bit];
    if (bit == -1) {
      bit = upTo;
    }
    outputNodes[firstNode[at]].ins.fra.frameNext = bit;
    outputNodes[firstNode[at]].ins.fra.next = goTo;
  } else if (beginsWith(line, "clr")) {
    outputNodes[firstNode[at]].ins.decJmp.nextZ = goTo;
  } else if (beginsWith(line, "jmp")) {
    int bit = getName(unres[at]);
    if (bit == -1) {
      printf ("Could not resolve name for %d\n", at);
      return;
    }
    bit = firstNode[bit];
    if (bit == -1) {
      bit = upTo;
    }
    outputNodes[firstNode[at]].ins.decJmp.nextZ = bit;
  } else if (beginsWith(line, "add")) {
    outputNodes[firstNode[at]].ins.decJmp.nextZ = goTo;
  }
}

int main() {
  while (!feof(stdin)) {
    fgets(lines[numLines++], 100, stdin);
    if (lines[numLines - 1][0] == '\n' || lines[numLines - 1][0] == 0) {
      numLines--;
    }
  }
  int i;
  rootNode = newMapNode();
  for (i = 0; i < numLines; i++) {
    fillInLine(i);
  }
  for (i = numLines - 1; i >= 0; i--) {
    if (firstNode[i] == -2) {
      firstNode[i] = firstNode[i + 1];
    }
  }
  for (i = 0; i < numLines; i++) {
    fixUpLine(i);
  }
  unsigned int numNodes = upTo;
  FILE* f = fopen("code", "wb");
  fwrite(&numNodes, 4, 1, f);
  for (i = 0; i < numNodes; i++) {
    fwrite(&outputNodes[i], sizeof (struct node), 1, f);
  }
  fclose(f);
  /*
  for (i = 0; i < numNodes; i++) {
    struct node *n = &outputNodes[i];
    if (n->type == INC) {
      printf ("%d inc %d %d\n", i, n->ins.inc.r, n->ins.inc.next);
    }
    if (n->type == DECJMP) {
      printf ("%d decjmp %d %d %d\n", i, n->ins.decJmp.r, n->ins.decJmp.nextNonZ, n->ins.decJmp.nextZ);
    }
    if (n->type == FRA) {
      printf ("%d fra %d %d %d\n", i, n->ins.fra.amo, n->ins.fra.frameNext, n->ins.fra.next);
    }
  }
  */
  return 0;
}
