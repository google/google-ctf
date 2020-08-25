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

#define _GNU_SOURCE
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/mount.h>
#include <sys/sendfile.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

static void wipe_directory(char *path) {
  DIR *d = opendir(path);
  if (d == NULL) {
    printf("opendir(%s): %m\n", path);
    return;
  }
  struct dirent *dent;
  while ((dent = readdir(d)) != NULL) {
    if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0)
      continue;
    if (unlinkat(dirfd(d), dent->d_name, 0))
      printf("unable to unlink %s/%s: %m\n", path, dent->d_name);
  }
  closedir(d);

  if (rmdir(path))
    printf("unable to unlink %s: %m\n", path);
}

int main(void) {
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  signal(SIGCHLD, SIG_IGN);

  if (mount("none", "/proc", "proc", MS_NODEV|MS_NOEXEC|MS_NOSUID, ""))
    err(1, "mount procfs");
  if (mount("none", "/tmp", "tmpfs", MS_NODEV|MS_NOEXEC|MS_NOSUID, ""))
    err(1, "mount /tmp");
  if (chdir("/tmp"))
    err(1, "chdir /tmp");

  int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (s == -1) err(1, "socket");
  int one = 1;
  if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)))
    err(1, "SO_REUSEPORT");
  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port = htons(1234),
    .sin_addr = { .s_addr = htonl(0) }
  };
  if (bind(s, (struct sockaddr *)&addr, sizeof(addr))) err(1, "bind");
  if (listen(s, 16)) err(1, "listen");

  sigset_t sigchld_mask;
  if (sigemptyset(&sigchld_mask)) err(1, "sigemptyset");
  if (sigaddset(&sigchld_mask, SIGCHLD)) err(1, "sigaddset");
  if (sigprocmask(SIG_BLOCK, &sigchld_mask, NULL)) err(1, "sigprocmask");
  int sigfd = signalfd(-1, &sigchld_mask, SFD_CLOEXEC|SFD_NONBLOCK);
  if (sigfd == -1) err(1, "signalfd");

  while (1) {
    int c = accept(s, NULL, NULL);
    if (c == -1) {
      /* not fatal, errors on a not-yet-accepted socket can cause this */
      perror("unable to accept connection");
      continue;
    }

    /* we have a new connection, spawn a child to handle it */
    write(c, "launching child process...\n", 27);
    pid_t child = fork();
    if (child == 0) {
      if (dup2(c, 0) == -1) err(1, "dup2");
      if (dup2(c, 1) == -1) err(1, "dup2");
      if (dup2(c, 2) == -1) err(1, "dup2");
      close(s);
      close(c);

      alarm(60);

      printf("please select an unguessable working directory for yourself, or specify an existing one:\n> ");
      char wd_name[100];
      for (int i=0; ; i++) {
        if (i == sizeof(wd_name))
          errx(1, "wd_name too long");
        char c;
        if (read(0, &c, 1) != 1)
          err(1, "reading working directory name");
        if (c == '\n') {
          if (i < 10)
            errx(1, "working directory name too short");
          wd_name[i] = '\0';
          break;
        } else if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == ' ' || c == '_') {
          wd_name[i] = c;
        } else {
          errx(1, "bad char '%c'", c);
        }
      }

      bool created = (mkdir(wd_name, 0700) == 0);
      if (!created && errno != EEXIST) err(1, "mkdir");
      if (chdir(wd_name)) err(1, "enter workdir");

      if (created) {
        printf("copying flagdb\n");
        int orig_fd = open("/flagdb", O_RDONLY|O_CLOEXEC);
        if (orig_fd == -1) err(1, "unable to open orig flagdb");
        int copy_fd = open("flagdb", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600);
        if (copy_fd == -1) err(1, "unable to open copy flagdb");
        struct stat st;
        if (fstat(orig_fd, &st)) err(1, "fstat");
        if (sendfile(copy_fd, orig_fd, NULL, st.st_size) != st.st_size)
          err(1, "unable to copy flagdb");
        close(orig_fd);
        close(copy_fd);
      }

      struct rlimit rlim_core = { .rlim_cur = 0, .rlim_max = 0 };
      if (setrlimit(RLIMIT_CORE, &rlim_core)) err(1, "RLIMIT_CORE");
      struct rlimit rlim_fsize = { .rlim_cur = 10000, .rlim_max = 10000 };
      if (setrlimit(RLIMIT_FSIZE, &rlim_fsize)) err(1, "RLIMIT_FSIZE");

      execl("/bin/database", "database", NULL);
      err(1, "execute database");
    }
    if (child == -1) {
      perror("fork handler child");
      write(c, "fork failed\n", 12);
    }
    close(c);


    /* try to delete anything older than 60s */
    time_t old_time = time(NULL) - 60;
    DIR *tmpdir = opendir(".");
    if (!tmpdir) {
      perror("temporary error opening /tmp");
      continue;
    }
    struct dirent *tmp_dent;
    while ((tmp_dent = readdir(tmpdir)) != NULL) {
      if (strcmp(tmp_dent->d_name, ".") == 0 || strcmp(tmp_dent->d_name, "..") == 0)
        continue;

      struct stat st;
      if (stat(tmp_dent->d_name, &st)) {
        perror("stat /tmp entry");
        continue;
      }
      if (st.st_ctime > old_time)
        continue;

      printf("cleaning up '%s'\n", tmp_dent->d_name);
      wipe_directory(tmp_dent->d_name);
    }
    closedir(tmpdir);
  }
}