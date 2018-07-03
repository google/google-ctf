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

#include <err.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

extern char **environ;
static char *unsafe[] = {
  "GCONV_PATH\x00",
  "GETCONF_DIR\x00",
  "HOSTALIASES\x00",
  "LD_AOUT_LIBRARY_PATH\x00",
  "LD_AOUT_PRELOAD\x00",
  "LD_AUDIT\x00",
  "LD_DEBUG\x00",
  "LD_DEBUG_OUTPUT\x00",
  "LD_DYNAMIC_WEAK\x00",
  "LD_LIBRARY_PATH\x00",
  "LD_ORIGIN_PATH\x00",
  "LD_PRELOAD\x00",
  "LD_PROFILE\x00",
  "LD_SHOW_AUXV\x00",
  "LD_USE_LOAD_BIAS\x00",
  "LOCALDOMAIN\x00",
  "LOCPATH\x00",
  "MALLOC_TRACE\x00",
  "NIS_PATH\x00",
  "NLSPATH\x00",
  "RESOLV_HOST_CONF\x00",
  "RES_OPTIONS\x00",
  "TMPDIR\x00",
  "TZDIR\x00",
  NULL,
};

static int lol(const void *a, const void *b)
{
  if ((unsigned long)a == (unsigned long)b)
    return 0;
  else if ((unsigned long)a > (unsigned long)b)
    return 1;
  else
    return -1;
}

static void shuffle(void)
{
  unsigned int n;
  char **q;

  n = 0;
  for (q = environ; *q != NULL; q++)
    n++;

  qsort(environ, n, sizeof(char *), lol);
}

/* reset unsafe variables */
static void filter_env(void)
{
  char **p;

  for (p = unsafe; *p != NULL; p++) {
    if (getenv(*p) != NULL) {
      if (setenv(*p, "", 1) != 0)
	err(1, "setenv");
    }
  }

  /* just be safe, prevent heap spraying attacks */
  shuffle();
}

static char **readenv(void)
{
  char **env = NULL;
  char line[1024];
  size_t len, n;

  n = 0;
  while (1) {
    if (fgets(line, sizeof(line), stdin) == NULL)
      break;

    len = strlen(line);
    if (len <= 1) {
      break;
    }

    if (++n > 32)
      errx(1, "can't allocate that much variables");

    env = realloc(env, n*sizeof(char*));
    if (env == NULL)
      err(1, "realloc");

    if (len > 0 && line[len-1] == '\n')
      line[len-1] = '\x00';

    env[n-1] = strdup(line);
    if (env[n-1] == NULL)
      err(1, "strdup");
  }

  if (env == NULL)
    errx(1, "no variable set\n");

  return env;
}

static void set_new_env(void)
{
  char **env;

  printf("[*] waiting for new environment\n");
  env = readenv();

  if (clearenv() != 0)
    err(1, "clearenv");

  environ = env;
  filter_env();
}

int main(void)
{
  char *arg[] = { "/usr/bin/id", NULL };

  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  if (setreuid(geteuid(), geteuid()) != 0)
    err(1, "setreuid");

  set_new_env();

  if (execvp(arg[0], arg) != 0)
    err(1, "execvp");

  /* never reached */
  return 0;
}
