// Copyright 2021 Google LLC
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

// This is intended to be executed on the secondary VM (the one that the
// contestants will not have access to). It is responsible for placing the first
// flag inside the device and the second one inside the kernel heap.
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  static const char flag[] = "CTF{D1ff3r3nT_D3v1Ce_S4mE_Tr1Ckz}";
  static const char flag2[64] = "CTF{B3h1nD_S3vEn_D4v1C3s}";
  static const char key[256] = "flag";

  char verify[64] = {};

  system("sysctl -w kernel.panic_on_oops=1");

  int f = open("/dev/pcivault", O_RDWR);
  if (f < 0) err(1, "open");

  // Set "encryption key"
  if (ioctl(f, 0, flag2) < 0) err(1, "ioctl");

  while (1) {
    // Set key
    if (ioctl(f, 1, key) < 0) err(1, "ioctl");
    // Write flag
    if (write(f, flag, sizeof(flag)) != sizeof(flag)) err(1, "writing flag");
    // Verify flag
    if (read(f, verify, sizeof(verify)) != sizeof(flag) || strcmp(verify, flag)) {
      fprintf(stderr, "Verifying flag failed\n");
    }
    sleep(2);
  }
  close(f);
  return 0;
}
