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



#include "objects.h"
#include "str.h"

#include <stdio.h>
#include <stdlib.h>

#define INT				0
#define STRING			1
#define MAP				2

#define IN_PRINTING 	-1

#define NUM_OBJECTS		20

struct object {
  int type;
  void *data;
  // Used for garbage collection.
  int reachable;
};

typedef struct mapEntry *MapEntry;

struct mapEntry {
  char name;
  Object ref;
  MapEntry next;
};

static Object rootO;

static int numAllocated;
static Object allObjects[NUM_OBJECTS];

static void traverse(Object at) {
  if (at->reachable) {
    return;
  }
  at->reachable = 1;
  if (at->type == MAP) {
    MapEntry m;
    for (m = at->data; m; m = m->next) {
      traverse(m->ref);
    }
  }
}

// Prepares the object for becoming a different type. Essentially frees all data
// associated with it.
static void freeData(Object o) {
  if (o->type == STRING) {
    freeStr(o->data);
  } else if (o->type == MAP) {
    MapEntry m = o->data;
    while (m) {
      MapEntry next = m->next;
      free(m);
      m = next;
    }
  }
}

static void freeObjects() {
  int i = 0;
  for (i = 0; i < NUM_OBJECTS; i++) {
    allObjects[i]->reachable = 0;
  }
  // We can assume the root object is allocated at this point.
  traverse(rootO);
  int at = 0;
  for (i = 0; i < NUM_OBJECTS; i++) {
    if (!allObjects[i]->reachable) {
      freeData(allObjects[i]);
      free(allObjects[i]);
    } else {
      allObjects[at++] = allObjects[i];
    }
  }
  numAllocated = at;
}

static Object getNewObject() {
  if (numAllocated == NUM_OBJECTS) {
    freeObjects();
    if (numAllocated == NUM_OBJECTS) {
      printf("Ran out of memory\n");
      exit(1);
    }
  }
  Object o = malloc(sizeof (struct object));
  allObjects[numAllocated++] = o;
  return o;
}

// This clones the name.
static MapEntry createMapEntry(Object in, char name, Object o) {
  if (in->type != MAP) {
    freeData(in);
    in->type = MAP;
    in->data = NULL;
  }
  MapEntry c;
  for (c = in->data; c; c = c->next) {
    if (c->name == name) {
      c->ref = o;
      return c;
    }
  }
  MapEntry m = malloc(sizeof (struct mapEntry));
  m->name = name;
  m->ref = o;
  m->next = in->data;
  in->data = m;
  return m;
}

static Object getRootObject() {
  if (rootO == NULL) {
    rootO = getNewObject();
    rootO->type = MAP;
    rootO->data = NULL;
  }
  return rootO;
}

static Object dereference(Object at, char name, int shouldCreate) {
  if (at->type != MAP) {
    if (!shouldCreate) {
      return NULL;
    }
    freeData(at);
    at->type = MAP;
    at->data = NULL;
  }
  MapEntry cur;
  for (cur = at->data; cur; cur = cur->next) {
    if (cur->name == name) {
      return cur->ref;
    }
  }
  if (!shouldCreate) {
    return NULL;
  }
  // Create a new reference.
  // This should only be called when we are going to assign. So create an INT
  // to avoid overhead.
  Object o = createFromInt(0);
  createMapEntry(at, name, o);
  return o;
}

static void printWithIndent(Object o, int indent) {
  switch(o->type) {
    case INT:
      printf("%lld\n", (long long) o->data);
      break;
    case STRING:
      printf("\"");
      fwrite(((Str) o->data)->data, 1, ((Str) o->data)->length, stdout);
      printf("\"\n");
      break;
    case MAP:
      // We can get into infinite loops, which is bad!
      // So prevent this by having a special class for things being printed.
      o->type = IN_PRINTING;
      printf("{\n");
      MapEntry e;
      for (e = o->data; e; e = e->next) {
        printf("%*s%c: ", indent + 2, "", e->name);
        printWithIndent(e->ref, indent + 2);
      }
      printf("%*s}\n", indent, "");
      o->type = MAP;
      break;
    case IN_PRINTING:
      printf("{ ... }\n");
      break;
  }
}

static void performAdd(char name, Object assignTo, Object add1, Object add2) {
  Object newO = getNewObject();
  createMapEntry(assignTo, name, newO);
  if (add1->type == MAP || add2->type == MAP) {
    newO->type = MAP;
    newO->data = NULL;
  } else if (add1->type == STRING || add2->type == STRING) {
    newO->type = STRING;
  } else {
    newO->type = INT;
  }
  if (add1->type == MAP) {
    MapEntry m1;
    for (m1 = add1->data; m1; m1 = m1->next) {
      if (add2->type == MAP) {
        MapEntry m2;
        int found = 0;
        for (m2 = add2->data; m2; m2 = m2->next) {
          if (m1->name == m2->name) {
            found = 1;
            break;
          }
        }
        if (found) {
          performAdd(m1->name, newO, m1->ref, m2->ref);
        } else {
          createMapEntry(newO, m1->name, m1->ref);
        }
      } else {
        performAdd(m1->name, newO, m1->ref, add2);
      }
    }
  }
  if (add2->type == MAP) {
    MapEntry m2;
    for (m2 = add2->data; m2; m2 = m2->next) {
      if (add1->type == MAP) {
        // In this case, we want to only add things that don't exist.
        MapEntry m1;
        int found = 0;
        for (m1 = add1->data; m1; m1 = m1->next) {
          if (m1->name == m2->name) {
            found = 1;
            break;
          }
        }
        if (!found) {
          createMapEntry(newO, m2->name, m2->ref);
        }
      } else {
        performAdd(m2->name, newO, add1, m2->ref);
      }
    }
  }
  if (add1->type != MAP && add2->type != MAP) {
    if (add1->type == STRING) {
      Str newData;
      if (add2->type == STRING) {
        newData = combineStr(add1->data, add2->data);
      } else {
        // Must be an INT.
        Str t = createStrFromInt((long long) add2->data);
        newData = combineStr(add1->data, t);
        freeStr(t);
      }
      newO->data = newData;
    } else {
      if (add2->type == STRING) {
        Str t = createStrFromInt((long long) add1->data);
        Str newData = combineStr(t, add2->data);
        freeStr(t);
        newO->data = newData;
      } else {
        newO->data = (void *) ((long long) add1->data + (long long) add2->data);
      }
    }
  }
}

Object createFromInt(long long v) {
  Object o = getNewObject();
  o->type = INT;
  o->data = (void *)v;
  return o;
}

Object createFromString(char *data, int length) {
  Object o = getNewObject();
  o->type = STRING;
  o->data = createStr(data, length);
  return o;
}

// If previous is null, search from root.
Object createFromName(char name, Object previous, int shouldCreate) {
  if (previous == NULL) {
    previous = getRootObject();
  }
  return dereference(previous, name, shouldCreate);
}

void printObject(Object o) {
  printWithIndent(o, 0);
}

// If previous is null, search from root.
void assignObject(Object assignTo, char name, Object assignFrom) {
  if (assignTo == NULL) {
    assignTo = getRootObject();
  }
  createMapEntry(assignTo, name, assignFrom);
}

// If previous is null, search from root.
void addObject(Object assignTo, char name, Object o1, Object o2) {
  if (assignTo == NULL) {
    assignTo = getRootObject();
  }
  performAdd(name, assignTo, o1, o2);
}
