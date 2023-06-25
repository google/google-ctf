// Copyright 2023 Google LLC
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

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "third_party/base64/base64.h"

#pragma pack(1)

struct ubf_packed {
  int block_size;
  char type;
  short count;
  short metadata_size;
  // metadata[metadata_size]
  // data[count]
};

struct ubf_unpacked {
  struct ubf_unpacked* next;
  char type;
  int count;
  int metadata_size;
  int raw_size;
  void* raw_data;
};

static char tmp_string[0x20000];
char* errorstr = "UNKNOWN ERROR";

#define ERROR_RETURN(_str) errorstr = _str; return NULL

void* unpack_bools(struct ubf_packed* packed, struct ubf_unpacked* unpacked, char* end) {
  char* src = (char*)(packed + 1);
  char* dst = (char*)unpacked->raw_data;
  int size = packed->count;
  
  if (size > packed->block_size || src + size > end) {
    ERROR_RETURN("Invalid bool content size");
  }
  
  memcpy(dst, src, size);
  return src + size;
}

void* unpack_ints(struct ubf_packed* packed, struct ubf_unpacked* unpacked, char* end) {
  char* src = (char*)(packed + 1);
  char* dst = (char*)unpacked->raw_data;
  int size = packed->count * sizeof(int);
  
  if (size > packed->block_size || src + size > end) {
    ERROR_RETURN("Invalid int content size");
  }
  
  memcpy(dst, src, size);
  return src + size;
}

void resize_rawbuf(struct ubf_unpacked* unpacked, int min_size) {
  int newsize = min_size * 2;
  void* newbuf = malloc(newsize);
  memcpy(newbuf, unpacked->raw_data, unpacked->raw_size);
  free(unpacked->raw_data);
  unpacked->raw_data = newbuf;
  unpacked->raw_size = newsize;
}

// Expand strings from env, insert into buf, possibly resize buf
void expand_string(char* str, int strsize, char** outstr, int* outstrsize) {
  if (strsize > 1 && str[0] == '$') {
    memcpy(tmp_string, str+1, strsize-1);
    tmp_string[strsize-1] = 0;
    const char* var = getenv(tmp_string);
    if (var != NULL) {
      int newsize = strlen(var);
      *outstr = (char*)var;
      *outstrsize = newsize <= 0xFFFF ? newsize : 0xFFFF;
      return;
    }
  }
  
  *outstr = str;
  *outstrsize = strsize;
}

void* unpack_strings(struct ubf_packed* packed, struct ubf_unpacked* unpacked, char* end) {
  char* dst = (char*)unpacked->raw_data;
  int dstoffset = packed->metadata_size;
  short* metadata = (short*)(packed + 1);
  char* src = (char*)metadata + packed->metadata_size;
  
  if (packed->metadata_size != packed->count * sizeof(short)) {
    ERROR_RETURN("Invalid string metadata");
  }
  
  if (packed->metadata_size > unpacked->raw_size) {
    ERROR_RETURN("String metadata out of bounds");
  }

  for (int i = 0; i < packed->count; ++i) {
    short size = metadata[i];
    char* expstr = NULL;
    int expsize = 0;
  
    if (size < 0 || src + size > end) {
      ERROR_RETURN("String data out of bounds");
    }
  
    expand_string(src, size, &expstr, &expsize);
    if (dstoffset + expsize > unpacked->raw_size) {
      resize_rawbuf(unpacked, dstoffset + expsize + 1);
      dst = (char*)unpacked->raw_data;
    }
  
    ((short*)dst)[i] = expsize;
    memcpy(dst + dstoffset, expstr, expsize);
    dst[dstoffset + expsize] = '\0';
    src += size;
    dstoffset += expsize + 1;
  }
  
  return src;
}

// Only allow 0 or 1 for our format
void fix_corrupt_booleans(struct ubf_unpacked* unpacked) {
  char* data = (char*)unpacked->raw_data + unpacked->metadata_size;
  char* end = (char*)unpacked->raw_data + unpacked->raw_size;
  for (int i = 0; i < unpacked->count; ++i) {
    if (data + i >= end) break;
    data[i] = !!data[i];
  }
}

// Unpack an entry, return start of next packed
struct ubf_packed* unpack_entry(struct ubf_packed* packed, char* end, struct ubf_unpacked** result) {
  struct ubf_unpacked* unpacked = malloc(sizeof(struct ubf_unpacked));
  struct ubf_packed* next = NULL;
  
  unpacked->next = NULL;
  unpacked->type = packed->type;
  unpacked->count = packed->count;
  unpacked->raw_size = packed->block_size;
  unpacked->metadata_size = packed->metadata_size;
  unpacked->raw_data = malloc(packed->block_size);
  
  if (!unpacked->raw_data) {
    ERROR_RETURN("Memory failure");
  }
  
  switch(packed->type) {
    case 'b':
      next = unpack_bools(packed, unpacked, end);
      fix_corrupt_booleans(unpacked);
      break;
    case 'i':
      next = unpack_ints(packed, unpacked, end);
      break;
    case 's':
      next = unpack_strings(packed, unpacked, end);
      break;
    default:
      ERROR_RETURN("Invalid type field");
  }
  
  *result = unpacked;
  return next;
}

#define APPEND( _fmt, ...) do { s += snprintf(s, end - s, _fmt, ##__VA_ARGS__); if (s >= end) { return NULL; } } while(0);

char* bools_tostr(struct ubf_unpacked* unpacked, char* s, char* end) {
  APPEND("bool [");

  char* booldata = (char*)unpacked->raw_data;
  for (int i = 0; i < unpacked->count; ++i) {
    char c = (booldata[i] == 0) ? 'F' : 'T';
    APPEND("%c, ", c);
  }
  
  if (unpacked->count > 0) {
    s -= 2; // drop last ", "
  }
  
  APPEND("]; ");
  return s;
}

char* ints_tostr(struct ubf_unpacked* unpacked, char* s, char* end) {
  APPEND("int [");

  int* intdata = (int*)unpacked->raw_data;
  for (int i = 0; i < unpacked->count; ++i) {
    APPEND("%d, ", intdata[i]);
  }
  
  if (unpacked->count > 0) {
    s -= 2; // drop last ", "
  }
  
  APPEND("]; ");
  return s;
}

void censor_string(char* s, int size) {
  if (size > 5 && s[0] == 'C' && s[1] == 'T' && s[2] == 'F' && s[3] == '{') {
    memset(s + 4, 'X', size - 5);
  } 
}

char* strs_tostr(struct ubf_unpacked* unpacked, char* s, char* end) {
  APPEND("str [");

  short* metadata = (short*)unpacked->raw_data;
  char* strdata = (char*)metadata + unpacked->metadata_size;
  for (int i = 0; i < unpacked->count; ++i) {
    censor_string(strdata, metadata[i]);
    APPEND("%s, ", strdata);
    strdata += metadata[i] + 1;
  }
  
  if (unpacked->count > 0) {
    s -= 2; // drop last ", "
  }
  
  APPEND("]; ");
  return s;
}

// Unpack a UBF into a string
char* unpack(void* data, int size) {
  struct ubf_packed* packed = (struct ubf_packed*)data;
  char* end = (char*)packed + size;
  void* unpacked_head = NULL;
  void** insert = &unpacked_head;
  
  do {
    // validate header
    if ((char*)packed + sizeof(struct ubf_packed) > end ||
        packed->count < 0 ||
        packed->block_size < 0) {
      ERROR_RETURN("Invalid header");
    }
  
    struct ubf_unpacked* unpacked = NULL;
    packed = unpack_entry(packed, end, &unpacked);
    if (packed == NULL) return NULL;
    
    *insert = unpacked; 
    insert = (void**)&unpacked->next;
  } while ((char*)packed < end);

  // Convert unpacked entries to string
  struct ubf_unpacked* cur = (struct ubf_unpacked*)unpacked_head;
  char* s = tmp_string;
  char* strend = tmp_string + sizeof(tmp_string) - 1;
  while(cur != NULL) {
    switch(cur->type) {
      case 'b': s = bools_tostr(cur, s, strend); break;
      case 'i': s = ints_tostr(cur, s, end); break;
      case 's': s = strs_tostr(cur, s, end); break;
      default: break;  
    }
    
    if (s == NULL) {
      ERROR_RETURN("Memory failure");
    }
  
    cur = cur->next;
  }
  
  s[0] = '\0';
  return tmp_string;
}

// Read ubf blob from stdin
void* read_blob_b64(int* size) {
  printf("Enter UBF data base64 encoded:\n");
  int i = 0;
  char c = 0;
  while (i < sizeof(tmp_string) - 1 && (c = getchar()) != '\n') {
    tmp_string[i++] = c;
  }
  tmp_string[i] = '\0';

  int reqsize = Base64decode_len(tmp_string); 
  char* data = malloc(reqsize);
  *size = Base64decode(data, tmp_string);
  
  return data;
}

void alarm_handler(int signum){ 
  printf("Exiting due to timeout\n");
  exit(-1);
}

int set_env_from_file(const char* name, const char* path) {
  FILE* f = fopen(path, "r");
  char tmpenv[512] = {0};
  if (f == NULL || fgets(tmpenv, sizeof(tmpenv), f) == NULL) {
    printf("Error reading %s\n", path);
    return 0;
  }
  int lastchr = strlen(tmpenv) - 1;
  if (tmpenv[lastchr] == '\n') tmpenv[lastchr] = 0;

  setenv(name, tmpenv, 1);
  return 1;
}

int main(int argc, char *argv[]) {
  // CTF configuration setup
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  signal(SIGALRM,alarm_handler);
  alarm(60);
  if (!set_env_from_file("FLAG", "/flag") ||
      !set_env_from_file("MOTD", "/motd") ||
      !set_env_from_file("TEAM", "/team")) {
    return -1;
  }
  
  int len = 0;
  void* data = read_blob_b64(&len);
  if (data == NULL && len <= 0) {
    printf("Invalid data provided\n");
    return -1;
  }

  char* result = unpack(data, len);
  if (result == NULL) result = errorstr;
  printf("%s\n", result);
  
  return 0;
}
