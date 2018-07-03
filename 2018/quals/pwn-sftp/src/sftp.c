// Copyright 2018 Google LLC
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     https://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "secure_allocator.h"

void readn(char* buf, size_t buf_len) {
  while (buf_len) {
    int result = fread(buf, 1, buf_len, stdin);
    if (result < 0) {
      abort();
    }
    buf += result;
    buf_len -= result;
  }
}

void writen(char* buf, size_t buf_len) {
  while (buf_len) {
    int result = fwrite(buf, 1, buf_len, stdout);
    if (result < 0) {
      abort();
    }
    buf += result;
    buf_len -= result;
  }
}

////////////////////////////////////////////////////////////////////////////////
// Handle authentication to the server
////////////////////////////////////////////////////////////////////////////////

char* user_name = "c01db33f";
char* host_name = "sftp.google.ctf";

bool authenticate_user() {
  char password[16];
  uint16_t hash = 0x5417;
  printf("%s@%s's password: ", user_name, host_name);
  if (scanf("%15s", password)) {
    getc(stdin);
    for (char* ptr = password; *ptr; ++ptr) {
      hash ^= *ptr;
      hash <<= 1;
    }
    if (hash == 36346) {
      return true;
    }
  }
  return false;
}

bool authenticate_server() {
  char response[4];
  printf(
      "The authenticity of host '%s (3.13.3.7)' can't be "
      "established.\n",
      host_name);
  printf(
      "ECDSA key fingerprint is "
      "SHA256:+d+dnKGLreinYcA8EogcgjSF3yhvEBL+6twxEc04ZPq.\n");
  printf("Are you sure you want to continue connecting (yes/no)? ");
  if (scanf("%3s", response) && !strcmp(response, "yes")) {
    printf(
        "Warning: Permanently added '%s' (ECDSA) to the list of "
        "known hosts.\n",
        host_name);
    return true;
  }
  return false;
}

bool authenticate() { return authenticate_server() && authenticate_user(); }

////////////////////////////////////////////////////////////////////////////////
// Handle the backing filesystem
////////////////////////////////////////////////////////////////////////////////

#define path_max 4096
#define name_max 20
#define file_max 65535

typedef struct entry entry;
typedef struct directory_entry directory_entry;
typedef struct file_entry file_entry;
typedef struct link_entry link_entry;
typedef struct link_table_entry link_table_entry;

enum entry_type {
  INVALID_ENTRY        = 0x0,
  DIRECTORY_ENTRY      = 0x1,
  FILE_ENTRY           = 0x2,
  LINK_ENTRY           = 0x4,
  DIRECTORY_LINK_ENTRY = DIRECTORY_ENTRY | LINK_ENTRY,
  FILE_LINK_ENTRY      = FILE_ENTRY | LINK_ENTRY,
};

struct entry {
  struct directory_entry* parent_directory;
  enum entry_type type;
  char name[name_max];
};

struct directory_entry {
  struct entry entry;

  size_t child_count;
  struct entry* child[];
};

struct file_entry {
  struct entry entry;

  size_t size;
  char* data;
};

struct link_entry {
  struct entry entry;

  struct entry* target;
};

directory_entry* root = NULL;
directory_entry* pwd = NULL;

bool is_absolute_path(char* path) { return (strlen(path) && path[0] == '/'); }

size_t entry_path_len(entry* ptr) {
  size_t path_len = 0;
  while (ptr) {
    path_len += strlen(ptr->name) + 1;
    ptr = (entry*)ptr->parent_directory;
  }
  return path_len;
}

void entry_path(entry* ptr, char* path) {
  char* path_ptr = &path[path_max - 1];
  memset(path, 0, path_max);
  while (ptr) {
    size_t name_len = strlen(ptr->name) + 1;
    if (path_ptr - name_len < path) {
      return;
    }
    path_ptr -= name_len;
    memcpy(path_ptr, ptr->name, name_len);
    *--path_ptr = '/';
    ptr = (entry*)ptr->parent_directory;
  }
  memmove(path, path_ptr, strlen(path_ptr));
}

entry* find_entry(char* path);
void delete_entry(entry* entry);
entry** new_entry(char* path);
directory_entry* find_directory(char* path);
file_entry* find_file(char* path);
link_entry* find_link(char* path);
directory_entry* new_directory(char* path);
file_entry* new_file(char* path);
link_entry* new_link(char* path);

entry* find_entry(char* path) {
  directory_entry* dir = pwd;
  char path_copy[path_max];
  strcpy(path_copy, path);
  path = path_copy;

  if (!strncmp(path, "/home/", 6)) {
    dir = root;
    path += 5;
  }

  char* name = strtok(path, "/");
  if (!name) {
    name = path;
  }

  size_t i = 0;
  while (i < dir->child_count) {
    if (dir->child[i] && !strcmp(dir->child[i]->name, name)) {
      name = strtok(NULL, "/");
      if (!name) {
        return dir->child[i];
      } else if (dir->child[i]->type == DIRECTORY_ENTRY) {
        dir = (directory_entry*)dir->child[i];
        i = 0;
        continue;
      } else if (dir->child[i]->type == DIRECTORY_LINK_ENTRY) {
        dir = (directory_entry*)((link_entry*)dir->child[i])->target;
        i = 0;
        continue;
      }
    }
    ++i;
  }

  return NULL;
}

void update_directory_links(directory_entry* dir, entry* old, entry* new) {
  for (size_t i = 0; i < dir->child_count; ++i) {
    entry* child = dir->child[i];
    if (child) {
      if (child->type & LINK_ENTRY) {
        link_entry* link = (link_entry*)child;
        if (link->target == old) {
          link->target = new;
        }
      } else if (child->type == DIRECTORY_ENTRY) {
        update_directory_links((directory_entry*)child, old, new);
      }
    }
  }
}

void update_links(entry* old, entry* new) {
  update_directory_links(root, old, new);
}

void delete_entry(entry* entry) {
  directory_entry* parent = entry->parent_directory;
  for (size_t i = 0; i < parent->child_count; ++i) {
    if (parent->child[i] == entry) {
      parent->child[i] = NULL;
      break;
    }
  }

  update_links(entry, NULL);
  free(entry);
}

entry** new_entry(char* path) {
  char path_copy[path_max];
  char* name = NULL;
  strcpy(path_copy, path);
  path = path_copy;

  name = strrchr(path, '/');
  if (!name) {
    name = path;
    path = NULL;
  } else {
    *name++ = 0;
  }

  directory_entry* parent = find_directory(path);
  entry** child = NULL;
  for (size_t i = 0; i < parent->child_count; ++i) {
    if (!parent->child[i]) {
      child = &parent->child[i];
      break;
    }
  }

  if (!child) {
    directory_entry* new_parent = realloc(parent, sizeof(directory_entry) + (parent->child_count * 2 * sizeof(entry*)));
    if (parent != new_parent) {
      update_links((entry*)parent, (entry*)new_parent);
      parent = new_parent;
    }

    for (size_t i = 0; i < parent->child_count; ++i) {
      parent->child[i]->parent_directory = parent;
    }

    child = &parent->child[parent->child_count];
    parent->child_count *= 2;
  }

  *child = malloc(sizeof(entry));
  (*child)->parent_directory = parent;
  (*child)->type = INVALID_ENTRY;
  strcpy((*child)->name, name);

  if (entry_path_len(*child) >= path_max) {
    delete_entry(*child);
    child = NULL;
  }

  return child;
}

directory_entry* find_directory(char* path) {
  if (!path) {
    return pwd;
  }

  entry* entry = find_entry(path);

  if (entry && entry->type == DIRECTORY_LINK_ENTRY) {
    entry = ((link_entry*)entry)->target;
  } else if (entry && entry->type != DIRECTORY_ENTRY) {
    entry = NULL;
  }

  return (directory_entry*)entry;
}

file_entry* find_file(char* path) {
  entry* entry = find_entry(path);

  if (entry && entry->type == FILE_LINK_ENTRY) {
    entry = ((link_entry*)entry)->target;
  } else if (entry && entry->type != FILE_ENTRY) {
    entry = NULL;
  }

  return (file_entry*)entry;
}

link_entry* find_link(char* path) {
  entry* entry = find_entry(path);

  if (entry && (entry->type & LINK_ENTRY) == 0) {
    entry = NULL;
  }

  return (link_entry*)entry;
}

directory_entry* new_directory(char* path) {
  directory_entry* dir = NULL;
  entry** child = new_entry(path);

  dir = realloc(*child, sizeof(directory_entry) + 16 * sizeof(entry*));
  dir->entry.type = DIRECTORY_ENTRY;
  dir->child_count = 16;
  memset(dir->child, 0, 16 * sizeof(entry*));

  return dir;
}

file_entry* new_file(char* path) {
  file_entry* file = NULL;
  entry** child = new_entry(path);

  file = realloc(*child, sizeof(file_entry));
  file->entry.type = FILE_ENTRY;
  file->size = 0;

  return file;
}

link_entry* new_link(char* path) {
  link_entry* link = NULL;
  entry** child = new_entry(path);

  link = realloc(*child, sizeof(link_entry));
  link->entry.type = LINK_ENTRY;
  link->target = NULL;

  return link;
}

#include "filesystem.h"

////////////////////////////////////////////////////////////////////////////////
// Handle the user commands
////////////////////////////////////////////////////////////////////////////////

bool handle_bye() { exit(0); }

bool handle_cd(char* path) {
  directory_entry* dir = find_directory(path);
  if (!dir) {
    printf("Couldn't stat remote file: No such file or directory\n");
  } else {
    pwd = dir;
  }
  return true;
}

bool handle_get(char* path) {
  file_entry* file = find_file(path);
  if (file) {
    printf("%zu\n", file->size);
    writen(file->data, file->size);
  } else {
    printf("File \"%s\" not found.\n", path);
  }

  return true;
}

bool handle_help() {
  printf("Available commands:\n");
  printf("bye                                Quit sftp\n");
  printf(
      "cd path                            Change remote directory to 'path'\n");
  printf("get remote                         Download file\n");
  printf(
      "ls [path]                          Display remote directory listing\n");
  printf("mkdir path                         Create remote directory\n");
  printf("put local                          Upload file\n");
  printf(
      "pwd                                Display remote working directory\n");
  printf("quit                               Quit sftp\n");
  printf("rm path                            Delete remote file\n");
  printf("rmdir path                         Remove remote directory\n");
  printf("symlink oldpath newpath            Symlink remote file\n");
  return true;
}

bool handle_ls(char* path) {
  directory_entry* dir = pwd;
  if (path) {
    dir = find_directory(path);
  }

  if (dir) {
    for (size_t i = 0; i < dir->child_count; ++i) {
      if (dir->child[i]) {
        printf("%s\n", dir->child[i]->name);
      }
    }
  } else {
    printf("Can't ls: \"%s\" not found\n", path);
  }

  return true;
}

bool handle_mkdir(char* path) {
  directory_entry* dir = NULL;
  entry* existing_entry = find_entry(path);
  if (!existing_entry) {
    dir = new_directory(path);
  }

  if (!dir) {
    printf("Couldn't create directory: Failure\n");
  }

  return true;
}

bool handle_put(char* path) {
  file_entry* file = NULL;
  entry* existing_entry = find_entry(path);
  if (existing_entry) {
    file = find_file(path);
  } else {
    file = new_file(path);
  }

  if (file) {
    char input_line[16];
    if (fgets(input_line, sizeof(input_line), stdin)) {
      size_t size;
      sscanf(input_line, "%zu", &size);
      if (file->size < size && size <= file_max) {
        file->data = malloc(size);
        file->size = size;
      } else if (file->size >= size) {
        memset(file->data, 0, size);
        file->size = size;
      } else {
        file->data = NULL;
        file->size = 0;
      }
      readn(file->data, file->size);
    }
  } else {
    printf("remote open(\"%s\"): No such file or directory\n", path);
  }

  return true;
}

bool handle_pwd() {
  char path[path_max];
  entry_path((entry*)pwd, path);
  printf("Remote working directory: %s\n", path);
  return true;
}

bool handle_rm(char* path) {
  link_entry* link = find_link(path);
  if (link) {
    delete_entry((entry*)link);
  } else {
    file_entry* file = find_file(path);
    if (file) {
      delete_entry((entry*)file);
    } else {
      printf("Couldn't remove file: No such file or directory\n");
    }
  }

  return true;
}

bool handle_rmdir(char* path) {
  directory_entry* dir = find_directory(path);
  if (dir) {
    delete_entry((entry*)dir);
  } else {
    printf("Couldn't remove directory: No such file or directory\n");
  }

  return true;
}

bool handle_symlink(char* src_path, char* path) { 
  link_entry* link = NULL;
  entry* target = find_entry(src_path);
  entry* existing_entry = find_entry(path);
  if (!existing_entry) {
    link = new_link(path);
  } else if (existing_entry->type & LINK_ENTRY) {
    link = (link_entry*)existing_entry;
  }

  if (link) {
    link->target = target;
    if (target && target->type == DIRECTORY_ENTRY) {
      link->entry.type = DIRECTORY_LINK_ENTRY;
    } else if (target && target->type == FILE_ENTRY) {
      link->entry.type = FILE_LINK_ENTRY;
    } else {
      link->entry.type = LINK_ENTRY;
    }
  } else {
    printf("Couldn't symlink \"%s\" to \"%s\": No such file or directory\n", src_path, path);
  }

  return true;
}

bool handle_invalid_command() {
  printf("Invalid command.\n");
  return true;
}

bool handle_command() {
  char input_line[10 + path_max + path_max];
  char src_path[path_max];
  char dst_path[path_max];

  printf("sftp> ");

  if (fgets(input_line, sizeof(input_line), stdin)) {
    if (!strncmp(input_line, "bye", 3)) {
      return handle_bye();
    } else if (!strncmp(input_line, "cd", 2)) {
      if (0 <= sscanf(input_line, "cd %4095s", dst_path)) {
        return handle_cd(dst_path);
      }
    } else if (!strncmp(input_line, "get", 3)) {
      if (0 <= sscanf(input_line, "get %4095s", dst_path)) {
        return handle_get(dst_path);
      }
    } else if (!strncmp(input_line, "help", 4)) {
      return handle_help();
    } else if (!strncmp(input_line, "ls", 2)) {
      if (0 <= sscanf(input_line, "ls %4095s", dst_path)) {
        return handle_ls(dst_path);
      }
      return handle_ls(NULL);
    } else if (!strncmp(input_line, "mkdir", 5)) {
      if (0 <= sscanf(input_line, "mkdir %4095s", dst_path)) {
        return handle_mkdir(dst_path);
      }
    } else if (!strncmp(input_line, "put", 3)) {
      if (0 <= sscanf(input_line, "put %4095s", dst_path)) {
        return handle_put(dst_path);
      }
    } else if (!strncmp(input_line, "pwd", 3)) {
      return handle_pwd();
    } else if (!strncmp(input_line, "quit", 4)) {
      return handle_bye();
    } else if (!strncmp(input_line, "rmdir", 5)) {
      if (0 <= sscanf(input_line, "rmdir %4095s", dst_path)) {
        return handle_rmdir(dst_path);
      }
    } else if (!strncmp(input_line, "rm", 2)) {
      if (0 <= sscanf(input_line, "rm %4095s", dst_path)) {
        return handle_rm(dst_path);
      }
    } else if (!strncmp(input_line, "symlink", 7)) {
      if (0 <=
          sscanf(input_line, "symlink %4095s %4095s", src_path, dst_path)) {
        return handle_symlink(src_path, dst_path);
      }
    }

    return handle_invalid_command();
  }

  return false;
}

void service_main() {
  if (authenticate()) {
    printf("Connected to %s.\n", host_name);
    while (handle_command())
      ;
  }
}

int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  service_main();
  
  return 0;
}
