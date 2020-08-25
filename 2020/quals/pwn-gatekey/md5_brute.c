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

/*
 * compile with gcc -O2 -o brute md5_brute.c -lcrypto
 * output:
 * [...]
 * found pair: "AKWMBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZA" hashes to "'4MxjGwcKykYEk5`"
 */

#include <openssl/md5.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>

static void md5_hash(unsigned char *out, char *data, unsigned long data_len) {
  MD5_CTX ctx;
  MD5_Init(&ctx);
  MD5_Update(&ctx, data, data_len);
  MD5_Final(out, &ctx);
}

static const unsigned long EXPECTED_ROUNDS = 627727202;
static const unsigned long CPUS = 56;
static int last_percent_done;

int main(void) {
  char input[65];
  memset(input, 'A', sizeof(input));
  input[64] = '\0';

  for (int i=0; ; i++) {
    if (i == CPUS) while (1) pause();
    pid_t child = fork();
    if (child == 0) {
      prctl(PR_SET_PDEATHSIG, SIGKILL);
      if (getppid() == 1) return 0;
      input[63] = 'A' + (i/26);
      input[62] = 'A' + (i%26);
      break;
    }
  }

  unsigned char hash[17];
  hash[16] = '\0';

  int iteration = 0;
  while (1) {
    iteration++;
    int percent_done = iteration / (EXPECTED_ROUNDS/CPUS);
    if (percent_done != last_percent_done) {
      last_percent_done = percent_done;
      printf("%d%% done of expected iterations\n", percent_done);
    }
    md5_hash(hash, input, sizeof(input));
    if (hash[0] != '\'') goto try_next;
    for (int i=1; i<16; i++) {
      char c = hash[i];
      if (c < 0x20 || c > 0x7e) {
        if (i > 12) printf("refusing %d at %d\n", c, i);
        goto try_next;
      }
    }
    printf("found pair: \"%s\" hashes to \"%s\"\n", input, hash);
    kill(getppid(), SIGTERM);
    return 0;
try_next:;

    for (int i=0; 1; i++) {
      if (input[i] == 'Z') {
        input[i] = 'A';
      } else {
        input[i]++;
        break;
      }
    }
  }
}
