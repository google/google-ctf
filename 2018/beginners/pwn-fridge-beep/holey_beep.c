/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <signal.h>
#include <err.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <linux/kd.h>

int device = -1;

void handle_sigterm(int unused) {
  if (device >= 0) {
    if (ioctl(device, KIOCSOUND, 0) < 0) {
      fprintf(stderr, "ioctl(%d, KIOCSOUND, 0) failed.", device);
      char debug_data[1024] = {0};
      read(device, debug_data, sizeof(debug_data)-1);
      fprintf(stderr, "debug_data: \"%s\"", debug_data);
    }
  }
  exit(0);
}

const char USAGE[] = "usage: holey_beep period1 [period2] [period3] [...]";

int main(int argc, char *argv[]) {
  if (signal(SIGTERM, handle_sigterm) == SIG_ERR) {
    err(1, "signal");
  }

  if (argc < 2) {
    errx(1, USAGE);
  }

  for (int i = 1; i < argc; i++) {
    device = open("dev/console", O_RDONLY);
    if (device < 0) {
      err(1, "open(\"dev/console\", O_RDONLY)");
    }

    int period = atoi(argv[i]);

    if (ioctl(device, KIOCSOUND, period) < 0) {
      fprintf(stderr, "ioctl(%d, KIOCSOUND, %d) failed.", device, period);
      close(device);
      continue;
    }
    close(device);
  }

  return 0;
}
