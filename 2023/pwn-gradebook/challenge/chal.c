// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/random.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>


typedef struct {
  char magic[4];
  int year;
  char name[32];
  char surname[32];
  size_t gradebook_size;
  size_t grade_head_offset;
  size_t empty_space_offset;
} gradebook;

typedef struct {
  char cl[8];
  char course[22];
  char grade[2];
  char teacher[12];
  char room[4];
  size_t period;
  size_t next_offset;
} entry;

volatile gradebook* grademap;
int gradefd;
size_t gradesz;

size_t read_int() {
  size_t i = 0;
  if (1 == scanf("%zu", &i)) {
    return i;
  }
  char c;
  scanf("%c", &c);
  return 0;
}

const char* prefix = "/tmp/grades_";
#define PREFIX_LEN 12
#define MAX_SZ 4096

void slow_putc(char c) {
  putchar(c);
  fflush(stdout);
  // UTF-8
  if ((c & 0xc0) != 0x80) {
    usleep(1000);
  }
}

void slow_puts(const char* s) {
  while (*s) {
    slow_putc(*s++);
  }
}

void slow_putn(size_t n) {
  char buf[32];
  sprintf(buf, "%zu", n);
  slow_puts(buf);
}

void slow_putsn(volatile char* s, size_t n) {
  while (*s && n--) {
    slow_putc(*s++);
  }
}

void slow_putspad(volatile char* s, size_t n) {
  while (*s && n--) {
    slow_putc(*s++);
  }
  if (n != SIZE_MAX) {
    while (n--) {
      slow_putc(' ');
    }
  }
}

void slow_putnpad(size_t n, size_t len) {
  char buf[32];
  sprintf(buf, "%zu", n);
  slow_putspad(buf, len);
}

void upload(const char* filename) {
  slow_puts("\n\n\nENTER FILE SIZE:\n");
  size_t sz;
  scanf("%zu", &sz);
  if (sz < 4) {
    slow_puts("INVALID SIZE\n");
    return;
  }
  if (sz > MAX_SZ) {
    slow_puts("FILE TOO LARGE\n");
    return;
  }
  slow_puts("\n\nSEND BINARY FILE DATA:\n");
  FILE* f = fopen(filename, "r+b");
  if (!f) { // File did not exist, let's create it.
    f = fopen(filename, "w+b");
    if (!f) {
      slow_puts("ERROR\n");
      return;
    }
  }
  char c;
  while (1) {
    c = fgetc(stdin);
    if (c == 'G') break;
  }
  fputc(c, f);
  for (size_t i = 1; i < sz; i++) {
    fputc(fgetc(stdin), f);
  }
  fclose(f);
}

int get_filename(char* filename) {
  slow_puts("ENTER FILENAME:\n");
  scanf("%60s", filename);
  for (int i = 0; i < 32; i++) {
    char c = filename[PREFIX_LEN + i];
    if (c >= '0' && c <= '9') {}
    else if (c >= 'a' && c <= 'f') {}
    else {
      return 1;
    }
  }
  if (strncmp(prefix, filename, PREFIX_LEN) || strlen(filename) != PREFIX_LEN+32) {
    return 1;
  }
  return 0;
}

void close_gradebook() {
  munmap((char*)grademap, gradesz);
  grademap = NULL;
  close(gradefd);
}

#define GRADEMAP_PTR ((char*)0x4752ade50000)

void win() {
  slow_puts("YOU WIN. HERE IS YOUR PRIZE:\n");
  system("cat /flag");
  exit(0);
}

void main_menu() {
  slow_puts("MENU:\n");
  slow_puts("1. OPEN STUDENT FILE\n");
  slow_puts("2. UPLOAD STUDENT FILE\n");
  slow_puts("3. QUIT\n");
  slow_puts("\n");
  int opt = read_int();
  char filename[64] = {0};
  if (opt == 1) {
    if (get_filename(filename)) {
      slow_puts("INVALID NAME\n");
      return;
    }
    gradefd = open(filename, O_RDWR);
    if (gradefd < 0) {
      slow_puts("ERROR\n");
      return;
    }
    struct stat statbuf;
    if (fstat(gradefd, &statbuf) < 0) {
      close(gradefd);
      slow_puts("ERROR\n");
      return;
    }
    gradesz = statbuf.st_size;
    grademap = mmap(GRADEMAP_PTR, gradesz, PROT_READ|PROT_WRITE, MAP_SHARED, gradefd, 0);
    if (grademap == MAP_FAILED || (char*)grademap != GRADEMAP_PTR) {
      close_gradebook();
      slow_puts("ERROR\n");
      return;
    }
    if (grademap->gradebook_size > gradesz
        || grademap->empty_space_offset > grademap->gradebook_size
        || grademap->empty_space_offset < sizeof(gradebook)) {
      printf("GRADEBOOK CORRUPTED\n");
      close_gradebook();
      return;
    }
  }
  else if (opt == 2) {
    if (get_filename(filename)) {
      slow_puts("FILE NOT FOUND. GENERATING RANDOM NAME.\n");
      strcpy(filename, prefix);
      unsigned char random_bytes[16];
      getrandom(random_bytes, 16, 0);
      for (int i = 0; i < 16; i++) {
        filename[PREFIX_LEN + i * 2] = "0123456789abcdef"[random_bytes[i] >> 4];
        filename[PREFIX_LEN + 1 + i * 2] = "0123456789abcdef"[random_bytes[i] & 0xf];
      }
      filename[PREFIX_LEN + 32] = 0;
      slow_puts("GENERATED FILENAME: ");
      slow_puts(filename);
      slow_puts("\n");
    }
    upload(filename);
  }
  else if (opt == 3) {
    exit(0);
  }
  else if (opt == 1337) {
    slow_puts("WELCOME PROFESSOR FALKEN. LET'S PLAY A GAME OF RUSSIAN ROULETTE.\n");
    unsigned char random_bytes[16];
    scanf("%c", &random_bytes[1]);
    for (size_t i = 0; i < 1000; i++) {
      scanf("%c", &random_bytes[1]);
      getrandom(random_bytes, 1, 0);
      if (random_bytes[0] < 256/6) {
        slow_puts("... *BAM!*\n-- CONNECTION TERMINATED --\n");
        exit(0);
      }
      else {
        slow_puts("... *click*\n");
      }
    }
    win();
  }
}

void put_buf(char* dst, volatile char* src, size_t srcsz) {
  while (srcsz-- && *src) {
    *dst++ = *src++;
  }
}

void put_bufn(char* dst, size_t n, size_t srcsz) {
  char buf[64];
  sprintf(buf, "%zu", n);
  put_buf(dst, buf, srcsz);
}

void list(volatile size_t* s, size_t) {
  // Force ordering in memory.
  struct {
    volatile entry* e;
    char buf[72];
  } leak;

  if (*s == 0) return;

  leak.e = (volatile entry*)(*s + (char*)grademap);
  memset(leak.buf, ' ', sizeof(leak.buf));
  leak.buf[66] = 0; // Works if room is 3 characters, not if 4!

//   M-122    CALCULUS 1             B      LOGAN        6       240
//0         1         2         3         4         5         6         7
//0123456789          0123456789          0123456789          0123456789          0123456789
//          0123456789          0123456789          0123456789          0123456789

  put_buf(leak.buf, "   ", 3);
  put_buf(leak.buf+3, leak.e->cl, 8);
  put_buf(leak.buf+12, leak.e->course, 22);
  put_buf(leak.buf+35, leak.e->grade, 2);
  put_buf(leak.buf+42, leak.e->teacher, 12);
  put_bufn(leak.buf+55, leak.e->period, 4);
  put_buf(leak.buf+63, leak.e->room, 4);
  slow_puts(leak.buf);
  slow_puts("\n");
}

size_t chosen_grade_id;

void remove_grade(volatile size_t* s, size_t i) {
  if (*s && i == chosen_grade_id) {
    volatile entry* e = (volatile entry*)(*s + (char*)grademap);
    *s = e->next_offset;
  }
}

void link_grade(volatile size_t* s, size_t) {
  if (*s == 0 && (char*)s - offsetof(entry, next_offset) - (char*)grademap != grademap->empty_space_offset) {
    *s = grademap->empty_space_offset;
  }
}

void update_grade(volatile size_t* s, size_t i) {
  if (*s && i == chosen_grade_id) {
    volatile entry* e = (volatile entry*)(*s + (char*)grademap);
    char grade[8] = {0};
    slow_puts("NEW GRADE:\n");
    scanf("%2s", grade);
    e->grade[0] = grade[0];
    e->grade[1] = grade[1];
  }
}

void loop(void(*fn)(volatile size_t*, size_t)) {
  volatile size_t* ptr = &grademap->grade_head_offset;
  size_t i = 1;
  while (*ptr) {
    if (*ptr >= grademap->gradebook_size || *ptr+sizeof(entry) > grademap->gradebook_size) {
      printf("GRADEBOOK CORRUPTED\n");
      close_gradebook();
      return;
    }
    fn(ptr, i++);
    ptr = &((volatile entry*)(*ptr+(char*)grademap))->next_offset;
  }
  fn(ptr, i++);
}

void second_menu() {
  {
    slow_puts("\n\n  ");
    slow_putn(grademap->year);
    slow_puts(", STUDENT NAME: ");
    slow_putsn(grademap->surname, 32);
    slow_puts(", ");
    slow_putsn(grademap->name, 32);
    slow_puts("\n\n\n\n");
    slow_puts("  CLASS #   COURSE TITLE         GRADE    TEACHER    PERIOD    ROOM\n");
    slow_puts("—————————————————————————————————————————————————————————————————————\n");
    loop(list);
    slow_puts("\n\n\n");
  }
  slow_puts("MENU:\n");
  slow_puts("1. ADD GRADE\n");
  slow_puts("2. UPDATE GRADE\n");
  slow_puts("3. REMOVE GRADE\n");
  slow_puts("4. DOWNLOAD GRADEBOOK\n");
  slow_puts("5. CLOSE GRADEBOOK\n");
  slow_puts("6. QUIT\n");
  slow_puts("\n");
  int opt = read_int();
  if (opt == 1) {
    if (grademap->empty_space_offset + sizeof(entry) > grademap->gradebook_size) {
      slow_puts("GRADEBOOK FULL\n");
    }
    else {
      volatile entry* e = (volatile entry*)(grademap->empty_space_offset + (char*)grademap);
      slow_puts("CLASS:\n");
      scanf("%8s", e->cl);
      slow_puts("COURSE TITLE:\n");
      scanf(" %22[^\n]", e->course);
      slow_puts("GRADE:\n");
      scanf("%2s", e->grade);
      slow_puts("TEACHER:\n");
      scanf("%12s", e->teacher);
      slow_puts("ROOM:\n");
      scanf("%4s", e->room);
      slow_puts("PERIOD:\n");
              //__asm__("int3");
              __asm__("nop");

      e->period = read_int();
      e->next_offset = 0;
      loop(link_grade);
      grademap->empty_space_offset += sizeof(entry);
    }
  }
  else if (opt == 2) {
    slow_puts("WHICH GRADE:\n");
    chosen_grade_id = read_int();
    loop(update_grade);
  }
  else if (opt == 3) {
    slow_puts("WHICH GRADE:\n");
    chosen_grade_id = read_int();
    loop(remove_grade);
  }
  else if (opt == 4) {
    slow_puts("\n\n\n");
    for (size_t i = 0; i < gradesz; i++) {
      slow_putc(((char*)grademap)[i]);
    }
    slow_puts("\n\n\n");
  }
  else if (opt == 5) {
    close_gradebook();
  }
  else if (opt == 6) {
    exit(0);
  }
}

int main() {
  slow_puts(
  "\nWELCOME TO THE GOOGLE PUBLIC SCHOOL DISTRICT DATANET\n\n"
  "PLEASE LOGON WITH USER PASSWORD:\n");
  char password[32];
  scanf("%30s", password);
  if (strcmp(password, "pencil")) {
    slow_puts("\nACCESS DENIED\n");
    return 0;
  }
  slow_puts("\nPASSWORD VERIFIED\n\n");

  while (1) {
    if (grademap == NULL) {
      main_menu();
    }
    else {
      second_menu();
    }
  }
}
