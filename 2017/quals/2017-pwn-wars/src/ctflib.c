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



/*
 ============================================================================
 Name        : ctflib.c
 Author      : Steven Vittitoe (scvitti@)
 Version     : 0.1
 ============================================================================
 */

#include "ctflib.h"

/*
 * This farms exit status from forked children to avoid
 * zombie processes lying around
 */

void sigchld(int sig) {
   int status;
   while (wait4(-1, &status, WNOHANG, NULL) > 0) {  }
}

/*
 * This reads up to size bytes into a user supplied buffer
 * Returns the number of bytes read or -1 if size bytes
 * could not be read.
 * This function is really only useful for reading fixed
 * size fields.
 */

int readAll(int fd, unsigned char *buf, unsigned int size) {
   unsigned int total = 0;
   int nbytes;
   while (total < size) {
      nbytes = recv(fd, buf + total, size - total, 0);
      if (nbytes <= 0) {
         return -1;
      }
      total += nbytes;
   }
   return (int)total;
}

/*
 * Read characters into buf until endchar is found. Stop reading when
 * endchar is read.  Returns the total number of chars read EXCLUDING
 * endchar.  endchar is NEVER copied into the buffer.  Note that it
 * is possible to perform size+1 reads as long as the last char read
 * is endchar.
 */

int read_until_delim(int fd, char *buf, unsigned int size, char endchar) {
   char ch;
   unsigned int total = 0;
   while (1) {
      if (read(fd, &ch, 1) <= 0) {
         return -1;
      }
      if (ch == endchar) break;
      if (total >= size) return -1;
      buf[total++] = ch;
   }
   return (int)total;
}

/*
 * Write the string contained in buf to the client socket
 * strlen is used to compute the length of buf.  If nullflag
 * is non-zero, then the null terminator is also written to
 * the client.
 */

int sendMsg(int fd, const char *buf, int nullflag) {
   unsigned int len = strlen(buf);
   return sendAll(fd, (unsigned char *)buf, nullflag ? (len + 1) : len);
}

/*
 * write size characters from buf to the client socket
 * returns -1 on error or size if all chars were
 * written.
 */

int sendAll(int fd, unsigned char *buf, unsigned int size) {
   unsigned int total = 0;
   while (total < size) {
      int nbytes = send(fd, buf + total, size - total, 0);
      if (nbytes == 0) return -1;
      total += nbytes;
   }
   return (int)total;
}

int sendFormat(int fd, const char *format, ...) {
   int result = 0;
   char *ptr = NULL;
   va_list argp;
   va_start(argp, format);
   if (vasprintf(&ptr, format, argp) == -1 || ptr == NULL) {
      result = -1;
   }
   else {
      result = sendMsg(fd, ptr, 0);
   }
   free(ptr);
   return result;
}

// Note this function is incorrectly implemented
// the minimum and maximum choice ranges are invalid
// because choice retains a value between loop iterations

int get_choice(int sock, int min, int max) {
  int choice = 0;
  char buf[8] = {0};
  while (read_until_delim(sock, buf, sizeof(buf)-1, '\n') > 0) {
    choice = strtol(buf, NULL, 0);
    if (choice >= min && choice <= max) {
      return choice;
    }
    memset(buf, 0, sizeof(buf));
    //choice = 0;
  }
  return choice;
}

int get_random_int(int min_num, int max_num) {
    srand(time(NULL));
    int result = 0;
    int low_num = 0;
    int hi_num = 0;

    if (min_num < max_num) {
        low_num = min_num;
        hi_num = max_num + 1;
    } else {
        low_num = max_num + 1;
        hi_num = min_num;
    }

    result = (rand() % (hi_num - low_num)) + low_num;
    return result;
}
/*
 * setup the server socket by binding to 0.0.0.0:port
 * SO_REUSEADDR is set on the socket.
 * returns the new server socket.
 */

int init(int port) {
   int fd;
   struct sockaddr_in my_addr;

   int one = 1;
   memset(&my_addr, 0, sizeof(my_addr));
   my_addr.sin_family = AF_INET;
   my_addr.sin_port = htons(port);
   if (signal(SIGCHLD, sigchld) == SIG_ERR) {
      err(-1, "Unable to set SIGCHLD handler");
   }
   fd = socket(AF_INET, SOCK_STREAM, 0);
   if (fd == -1) {
      err(-1, "Unable to create socket");
   }
   if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1) {
      err(-1, "Unable to set reuse");
   }
   if (bind(fd, (struct sockaddr*)&my_addr, sizeof(my_addr)) == -1) {
      err(-1, "Unable to bind socket");
   }
   if (listen(fd, 20) == -1) {
      err(-1, "Unable to listen on socket");
   }
   return fd;
}

/*
 * Enter a forking accept loop.  Call the client_callback
 * function for each new client connection.
 */
void loop(int server_sock, callback client_func) {
   int loop = 1;
   while (loop) {
      struct sockaddr_in peer;
      unsigned int peer_len = sizeof(peer);
      int client = accept(server_sock, (struct sockaddr*)&peer, &peer_len);
      if (client != -1) {
         int pid = fork();
         if (pid != -1) {
            if (pid == 0) { //child
               close(server_sock);
               int result = (*client_func)(client);
               close(client);
               exit(result);
            }
            else {
               close(client);
            }
         }
      }
   }
}

/*
 * Drop privileges to the specified user account
 */
int drop_privs_user(const char *user_name) {
   struct passwd *pw = getpwnam(user_name);
   if (pw == NULL) {
      err(-1, "Failed to find user %s\n", user_name);
   }
   if (drop_privs(pw) == -1) {
      err(-1, "drop_privs failed!\n");
   }
   return 0;
}

/*
 * Do the real work of dropping privileges.  Checks to
 * see what the current uid/gid are, sets res gid and
 * uid to the specified user's uid/gid and verifies
 * that privs can't be restored to the initial uid/gid
 */
int drop_privs(struct passwd *pw) {
   int uid = getuid();
   int gid = getgid();

   initgroups(pw->pw_name, pw->pw_gid);
   if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) < 0) return -1;
   if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) < 0) return -1;
   if (pw->pw_gid != gid && (setgid(gid) != -1 || setegid(gid) != -1)) {
      printf("setgid current gid: %d target gid: %d\n", getgid(), pw->pw_gid);
      return -1;
   }
   if (pw->pw_uid != uid && (setuid(uid) != -1 || seteuid(uid) != -1)) {
      printf("setgid current uid: %d target uid: %d\n", getuid(), pw->pw_uid);
      return -1;
   }
   if (getgid() != pw->pw_gid || getegid() != pw->pw_gid) return -1;
   if (getuid() != pw->pw_uid || geteuid() != pw->pw_uid) return -1;
   return chdir(pw->pw_dir);
}
