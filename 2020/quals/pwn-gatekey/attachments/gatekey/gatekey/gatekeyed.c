/*
 * Copyright 2020 Google LLC
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

#include "internal.h"
#include "gatekey_api.h"
#include "../../../../../../third_party/openwall-md5/md5.h"
#include <stdarg.h>
#include <asm/errno.h>
#include <asm/unistd_64.h>
#include <asm/fcntl.h>

char key_gate_stack[KEY_GATE_STACK_SIZE] __attribute__((aligned(4096)));
unsigned int gatekey_trusted_key_state;
unsigned int gatekey_normal_key_state;

/* ensure that we have a non-empty data section for sanity checks */
unsigned int __gatekey_force_nonempty_data_section = 1;

const struct open_how permitted_open_how[2] = {
  {
    .flags = O_RDWR|O_CLOEXEC,
    .resolve = RESOLVE_BENEATH
  },
  {
    .flags = O_RDWR|O_CLOEXEC|O_CREAT|O_EXCL,
    .mode = 0600,
    .resolve = RESOLVE_BENEATH
  }
};

static long do_pwrite(unsigned long fd, void *data, unsigned long len, unsigned long offset) {
  return gatekey_syscall(fd, (unsigned long)data, len, 0, 0, __NR_pwrite64);
}

static long do_pread(unsigned long fd, void *data, unsigned long len, unsigned long offset) {
  return gatekey_syscall(fd, (unsigned long)data, len, offset, 0, __NR_pread64);
}

static void write_stdout(char *data, unsigned long len) {
  if (len == 0)
    return;
  gatekey_syscall(1, (unsigned long)data, len, 0, 0, __NR_write);
}

static unsigned long strlen(char *p) {
  char *start = p;
  while (*p) p++;
  return p - start;
}

static void simple_printf(char *arg, ...) {
  va_list ap;
  char *print_end = arg;
  va_start(ap, arg);

  while (*arg) {
    if (*arg == '%') {
      write_stdout(print_end, arg - print_end);
      arg++;
      switch (*arg) {
      case 'u':;
        char buf[100];
        char *bufp = buf + sizeof(buf);
        unsigned long num = va_arg(ap, unsigned long);
        do {
          *(--bufp) = (num % 10) + '0';
          num /= 10;
        } while (num != 0);
        write_stdout(bufp, buf + sizeof(buf) - bufp);
        break;
      case 's':;
        char *str = va_arg(ap, char*);
        unsigned long str_len = va_arg(ap, unsigned long);
        write_stdout(str, str_len);
        break;
      default:
        write_stdout("<bad format element>\n", 21);
        break;
      }
      arg++;
      print_end = arg;
    } else {
      arg++;
    }
  }
  write_stdout(print_end, arg - print_end);
  va_end(ap);
}

static int access_ok(void *ptr_, unsigned long len) {
  unsigned long ptr = (unsigned long)ptr_;
  unsigned long end = ptr + len;
  if (end < ptr)
    return 0;
  if (end > (unsigned long)_gatekey_data_begin && ptr < (unsigned long)_gatekey_data_end)
    return 0;
  if (end >= (unsigned long)_gatekey_bss_begin && ptr < (unsigned long)_gatekey_bss_end)
    return 0;
  return 1;
}

static int do_open(char *path, const struct open_how *how) {
  int fd = gatekey_syscall(AT_FDCWD, (unsigned long)path, (unsigned long)how, sizeof(struct open_how), 0, __NR_openat2);
  if (fd < 0)
    simple_printf("'%s' could not be opened: -%u\n", path, strlen(path), (unsigned long)-fd);
  return fd;
}

static void do_close(int fd) {
  gatekey_syscall(fd, 0, 0, 0, 0, __NR_close);
}

static void md5_hash(unsigned char *out, char *data, unsigned long data_len) {
  MD5_CTX ctx;
  MD5_Init(&ctx);
  MD5_Update(&ctx, data, data_len);
  MD5_Final(out, &ctx);
}

static unsigned long handle_open(struct gatekey_args *args) {
  long err;

  /* open an existing file */
  int fd = do_open(args->path, permitted_open_how);
  if (fd < 0)
    return fd;

  /* ensure that the user has a valid key for the file */
  unsigned char authkey_hash_a[16], authkey_hash_b[16];
  md5_hash(authkey_hash_a, args->authkey, sizeof(args->authkey));
  err = do_pread(fd, authkey_hash_b, sizeof(authkey_hash_b), 0);
  if (err != sizeof(authkey_hash_b)) {
    simple_printf("unable to read authkey for '%s': -%u\n",
                  args->path, strlen(args->path),
                  (unsigned long)-err);
    do_close(fd);
    return -EKEYREJECTED;
  }
  for (int i=0; i<16; i++) {
    if (authkey_hash_a[i] == authkey_hash_b[i])
      continue;
    simple_printf("'%s' is not the correct authkey for '%s'\n",
                  args->authkey, sizeof(args->authkey),
                  args->path, strlen(args->path));
    do_close(fd);
    return -EKEYREJECTED;
  }

  /* all good */
  return fd;
}

static unsigned long handle_create(struct gatekey_args *args) {
  /* create a new file */
  int fd = do_open(args->path, permitted_open_how+1);
  if (fd < 0)
    return fd;

  /* generate an ASCII authorization key for the file */
  long err = gatekey_syscall((unsigned long)args->authkey, sizeof(args->authkey), 0, 0, 0, __NR_getrandom);
  if (err != sizeof(args->authkey)) {
    simple_printf("getrandom failed for %s: %u\n",
                  args->path, strlen(args->path),
                  (unsigned long)-err);
    goto out_err;
  }
  for (int i=0; i<sizeof(args->authkey); i++)
    args->authkey[i] = (args->authkey[i] & 0x1f) | 0x40;
  simple_printf("generated authkey '%s' for %s\n",
                args->authkey, sizeof(args->authkey),
                args->path, strlen(args->path));

  /* store a hash of the authorization key in the file */
  unsigned char authkey_hash[16];
  md5_hash(authkey_hash, args->authkey, sizeof(args->authkey));
  err = do_pwrite(fd, authkey_hash, sizeof(authkey_hash), 0);
  if (err != sizeof(authkey_hash)) {
    simple_printf("failed writing authkey hash\n");
    goto out_err;
  }

  /* return the created file */
  return fd;

out_err:
  do_close(fd);
  return (err < 0) ? err : -EDOM;
}

unsigned long gatekey_call_handler(struct gatekey_args *args) {
  if (!access_ok(args, sizeof(*args))) {
    simple_printf("args pointer points to gatekey area\n");
    return -1;
  }

  switch (args->op) {
  case GATEKEY_OP_OPEN:
    return handle_open(args);
  case GATEKEY_OP_CREATE:
    return handle_create(args);
  default:
    simple_printf("unknown op %u\n");
    return 0;
  }
}
