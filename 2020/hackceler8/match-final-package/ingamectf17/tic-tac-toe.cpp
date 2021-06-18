// Copyright 2020 Google LLC
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
#include <cstdio>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>

void append_file(const char *filename, const char *buf) {
  int fd = open(filename, O_RDWR);
  if(fd < 0) {
    printf("Unable to open file %s!\n", filename);
    return;
  }
  lseek(fd, 0, SEEK_END);
  size_t remaining = strlen(buf);
  while(remaining) {
    ssize_t nwritten = write(fd, buf, remaining);
    if(nwritten <= 0)
      goto end;
    remaining -= nwritten;
    buf += nwritten;
  }
end:
  close(fd);
}

void dump_file(const char *filename) {
  int fd = open(filename, O_RDONLY);
  if(fd < 0) {
    printf("Unable to open file %s!\n", filename);
    return;
  }
  char buf[4096];
  while(true) {
    ssize_t nread = read(fd, buf, sizeof(buf));
    if(nread <= 0)
      break;
    size_t already_written = 0;
    while(already_written < nread) {
      ssize_t nwritten = write(STDOUT_FILENO, buf + already_written, nread - already_written);
      if(nwritten <= 0) {
        goto end;
      }
      already_written += nwritten;
    }
  }
  end:
  close(fd);
  fflush(stdout);
}

char *read_string(const char *msg) {
  char buf[128];
  printf("%s", msg);
  fflush(stdout);
  size_t already = 0;
  while(true) {
    ssize_t nread = read(STDIN_FILENO, buf + already, 0x128 - already);
    if(nread <= 0)
      return NULL;
    already += nread;
    if(buf[already - 1] == '\n' || already >= sizeof(buf)) {
      size_t sz = strlen(buf);
      if(sz > already)
        sz = already;
      char *res = (char*)calloc(1, sz + 1);
      memcpy(res, buf, sz);
      return res;
    }
  }
}

static const int PLAYER = 1;
static const int COMPUTER = 2;
char board[3][3];

void dump_board() {
  char chars[] = " XO";
  for(int y = 0; y < 3; y++) {
    char line[] = "| ? | ? | ? |";
    for(int x = 0; x < 3; x++) {
      line[2 + (4 * x)] = chars[board[x][y]];
    }
    printf("+---+---+---+\n%s\n", line);
  }
  printf("+---+---+---+\n");
}

int who_wins() {
  int winner;
  for(int i = 0; i < 3; i++) {
    winner = board[0][i] & board[1][i] & board[2][i];
    if(winner)
      return winner;
    winner = board[i][0] & board[i][1] & board[i][2];
    if(winner)
      return winner;
  }
  winner = board[0][0] & board[1][1] & board[2][2];
  if(winner)
    return winner;
  winner = board[2][0] & board[1][1] & board[0][2];
  if(winner)
    return winner;
  for(int y = 0; y < 3; y++)
    for(int x = 0; x < 3; x++)
      if(board[x][y] == 0)
        return 0;
  return COMPUTER|PLAYER;
}

void player_turn() {
  while(true) {
    char *pos = read_string("Enter X & Y coords: [123] [123]\n");
    int x = pos[0] - '1';
    int y = pos[2] - '1';
    free(pos);
    if(x >= 0 && x < 3 && y >= 0 && y <= 3 && !board[x][y]) {
      board[x][y] = PLAYER;
      return;
    }
    printf("Invalid turn\n");
  }
}

int fd_urandom = -1;

void computer_turn() {
  if(fd_urandom == -1) {
    fd_urandom = open("/dev/urandom", O_RDONLY);
  }
  unsigned char rnd;
  while(true) {
    if(read(fd_urandom, &rnd, 1) != 1) {
      printf("Unable to read urandom\n");
      exit(1);
    }
    if((rnd & 15) == 15 || (rnd >> 4) == 15)
      continue;
    char &pos = board[(rnd & 15) % 3][(rnd >> 4) % 3];
    if(pos)
      continue;
    printf("Computer places at %d %d.\n", 1 + ((rnd & 15) % 3), 1 + ((rnd >> 4) % 3));
    pos = COMPUTER;
    return;
  }
}

int round() {
  memset(board, 0, sizeof(board));
  bool player = true;
  while(true) {
    dump_board();
    if(player)
      player_turn();
    else
      computer_turn();
    player = !player;
    int winner = who_wins();
    if(winner) {
      const char *name[] = {"Player", "Computer", "Nobody"};
      printf("%s wins!\n", name[winner - 1]);
      return winner;
    }
  }
}

int game() {
  int score = 0;
  while(true) {
    switch(round()) {
      case COMPUTER:
        return score;
      case PLAYER:
        score++;
      default:
        printf("Score: %d\n", score);
    }
  }
}

int main(int argc, char **argv) {
  if(argc != 2) {
    printf("Usage: %s <directory to data files>\n", argv[0]);
    return 1;
  }
  dump_file(argv[0]);
  chdir(argv[1]);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  while(true) {
    pid_t pid = fork();
    if(pid < 0) {
      printf("fork failed.\n");
      return 1;
    }
    if(pid > 0) {
      int status = 0;
      waitpid(pid, &status, 0);
      char *choice = read_string("Do you want to play another round? [y/n]\n");
      bool another_game = (choice[0] & ~0x20) == 'Y';
      free(choice);
      if(!another_game)
        return 0;
      continue;
    }
    dump_file("where_is_the_flag.txt");
    char *name = read_string("Please enter your name: ");
    printf("Hello %s!\n", name);

    int score = game();

    char line[1024];
    snprintf(line, sizeof(line), "%-10d %s\n", score, name);
    free(name);
    line[sizeof(line)-1] = 0;
    append_file("scoreboard.txt", line);

    printf("Scoreboard:\n");
    dump_file("scoreboard.txt");
    return 0;
  }
}
