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



#define _GNU_SOURCE
#include <linux/random.h>
#include <err.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>

int64_t check(int64_t ret, const char *msg) {
  if (ret == -1) {
    err(1, "%s", msg);
  }
  return ret;
}

uint64_t epoch;
uint64_t gc_tag;
void *heap_start;

struct heap_metadata {
  uint64_t epoch;
  size_t sz;
  uint64_t tag;
};

struct global_list {
  void *ptr;
  struct global_list *next;
} *globals = NULL;

void *gcalloc(size_t sz) {
  size_t total_sz = sz + sizeof(struct heap_metadata);
  if (total_sz < sz) {
    err(1, "gcalloc");
  }

  struct heap_metadata* meta = malloc(total_sz);
  if (!meta) {
    err(1, "malloc");
  }

  meta->epoch = epoch;
  meta->tag = gc_tag;
  meta->sz = sz;

  char *data = (char*) (meta+1);
  memset(data, 0, meta->sz);

  return data;
}

void *gcalloc_global(size_t sz) {
  void *ptr = gcalloc(sz);

  struct global_list *global = malloc(sizeof(struct global_list));
  if (!global) {
    err(1, "malloc");
  }

  global->ptr = ptr;
  global->next = globals;
  globals = global;

  return ptr;
}

void mark(struct heap_metadata *meta) {
  if ((void*) meta < heap_start || (void*) meta >= sbrk(0)) {
    return;
  }

  if (meta->tag != gc_tag) {
    return;
  }

  if (meta->epoch == epoch) {
    return;
  }

  meta->epoch = epoch;
  struct heap_metadata **ptr = (struct heap_metadata **) (meta+1);
  for (size_t i = 0; i < meta->sz/sizeof(ptr); i++) {
    mark(ptr[i]-1);
  }
}

void sweep(struct heap_metadata *meta) {
  if (meta->tag == gc_tag && meta->epoch == epoch-1) {
    free(meta);
  }
}

void run_gc() {
  puts("gc start");

  epoch++;
  void *heap_end = sbrk(0) - sizeof(struct heap_metadata);

  for (struct global_list *global = globals; global; global = global->next) {
    mark(((struct heap_metadata *)global->ptr)-1);
  }

  for (void *ptr = heap_start; ptr < heap_end; ptr+=sizeof(void*)) {
    sweep(ptr);
  }

  puts("gc end");
}

void free_globals() __attribute__((destructor));
void free_globals() {
  struct global_list *global = globals;
  while (global) {
    struct global_list *next = global->next;
    free(global);
    global = next;
  }
  run_gc();
}

struct tree {
  struct tree **trees;
  char *data;
} **trees = NULL;

const int TREE_CNT = 10;

void install_gc() __attribute__((constructor));
void install_gc() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  heap_start = malloc(0);
  if (!heap_start) {
    err(1, "malloc(0)");
  }
  free(heap_start);

  check(syscall(SYS_getrandom, &gc_tag, sizeof(gc_tag), 0), "getrandom");
  check(syscall(SYS_getrandom, &epoch, sizeof(epoch), 0), "getrandom");

  trees = gcalloc_global(sizeof(struct tree*)*TREE_CNT);
}

const char menu[] =
"0) new node\n"
"1) print\n"
"2) copy node\n"
"3) gc\n"
"*) quit";

int read_int() {
  int ret;
  if (scanf("%d", &ret) != 1) {
    err(1, "scanf");
  }
  getchar();
  return ret;
}

struct tree **read_tree_pos() {
  printf("tree position? ");

  struct tree **tree_pos = NULL;
  do {
    int idx;
    if (scanf(" %d", &idx) != 1) {
      err(1, "scanf");
    }
    if (idx < 0 || idx >= TREE_CNT) {
      exit(1);
    }
    if (!tree_pos) {
      tree_pos = &trees[idx];
    } else {
      if (!*tree_pos) {
        exit(1);
      }
      tree_pos = &(*tree_pos)->trees[idx];
    }

  } while(getchar() != '\n');

  return tree_pos;
}

void read_all(char *buf, size_t sz) {
  while (sz) {
    ssize_t cnt = read(0, buf, sz);
    if (cnt <= 0) {
      err(1, "read");
    }
    sz -= cnt;
    buf += cnt;
  }
}

void new_node() {
  struct tree **tree_pos = read_tree_pos();
  struct tree *tree = gcalloc(sizeof(struct tree));
  *tree_pos = tree;
  tree->trees = gcalloc(sizeof(struct tree*)*TREE_CNT);

  size_t sz;
  printf("data len? ");
  if (scanf("%zu", &sz) != 1) {
    err(1, "scanf");
  }
  getchar();
  if (sz > 4096) {
    sz = 4096;
  }

  tree->data = gcalloc(sz+1);
  read_all(tree->data, sz);
}

void print_tree(int indent, struct tree *tree) {
  if (!tree) {
    return;
  }
  printf("%*sdata: %s\n", indent, "", tree->data);
  printf("%*ssubtrees:\n", indent, "");
  for (int i = 0; i < TREE_CNT; i++) {
    if (!tree->trees[i]) {
      continue;
    };
    printf("%*s%2d)\n", indent, "", i);
    print_tree(indent+2, tree->trees[i]);
  }
}

void print() {
  struct tree **tree_pos = read_tree_pos();
  print_tree(0, *tree_pos);
}

void copy_node() {
  printf("from ");
  struct tree **from = read_tree_pos();
  printf("to ");
  struct tree **to = read_tree_pos();
  *to = *from;
}

int main(int argc, char *argv[]) {
  while (1) {
    puts(menu);
    switch(read_int()) {
      case 0:
        new_node();
        break;
      case 1:
        print();
        break;
      case 2:
        copy_node();
        break;
      case 3:
        run_gc();
        break;
      default:
        exit(0);
    }
  }
}
