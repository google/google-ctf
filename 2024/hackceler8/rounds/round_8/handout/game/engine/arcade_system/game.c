#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#define W 20
#define H 22
#define TW 32
#define TH 32

#define WON 'W'
#define NOT_WON '\x00'

#define WALL 6
#define PIECE 5

#define BOARD_W 16

int tics = 0;
char screen[W*H] = { 0 };
int w_pressed = 0, a_pressed = 0, s_pressed = 0, d_pressed = 0, space_pressed = 0, prev_space_pressed = 0;

// Compressed tetris piece data
char* comp_pieces = "\x06\x60\x06\x60\x06\x60\x06\x60\x0e\x20\x44\xc0\x8e\x00\x64\x40\x0e\x40\x4c\x40\x4e\x00\x46\x40\x26\x40\x0c\x60\x4c\x80\xc6\x00\xf0\x00\x44\x44\xf0\x00\x44\x44";
# define PIECE_COUNT 5
# define PIECE_SIZE 4
# define ROT_COUNT 4
char pieces[PIECE_COUNT][ROT_COUNT][PIECE_SIZE][PIECE_SIZE] = { 0 };

struct BoardState {
  int piece_x, piece_y, piece, rot;
  char board[BOARD_W*2];
  long board_h;
  int prev_y, prev_x;
};

int should_draw(char* cmd) {
  if (strlen(cmd) < 4) {
    exit(1);
  }
  return strncmp("DRAW", cmd, 4) == 0;
}

int should_tick(char* cmd) {
  if (strlen(cmd) < 4) {
    exit(1);
  }
  return strncmp("TICK", cmd, 4) == 0;
}

void draw() {
  for (int i = 0; i < W*H; ++i) putc(screen[i], stdout);
  fflush(stdout);
}

void process_cmds_until_tick() {
  while (1) {
    char *cmd = NULL;
    size_t sz = 0;
    if (getline(&cmd, &sz, stdin) == -1) {
      exit(1);
    }
    if (should_draw(cmd)) {
      draw();
      continue;
    } else if (should_tick(cmd)) {
      tics += 1;
      if (strlen(cmd) < 10) {
        exit(1);
      }
      w_pressed = cmd[5] == '1';
      a_pressed = cmd[6] == '1';
      s_pressed = cmd[7] == '1';
      d_pressed = cmd[8] == '1';
      prev_space_pressed = space_pressed;
      space_pressed = cmd[9] == '1';
      return;
    } else {
      exit(1);
    }
    free(cmd);
  }
}

int is_solid(char* board, int x, int y) {
  if (board == NULL) return 0;
  int pos = y * BOARD_W + x;
  int byte = pos / 8;
  int bit = 1 << (7 - pos % 8);
  return board[byte] & bit;
}

void put(char* board, int x, int y, int piece) {
  int pos = y * BOARD_W + x;
  int byte = pos / 8;
  int bit = 1 << (7 - pos % 8);
  if (piece) board[byte] |= bit;
  else board[byte] &= ~bit;
}

void remove_piece(char* board, int x, int y, char piece[PIECE_SIZE][PIECE_SIZE]) {
  for (int yy = 0; yy < PIECE_SIZE; ++yy)
    for (int xx = 0; xx < PIECE_SIZE; ++xx)
      if (piece[yy][xx]) put(board, x + xx, y + yy, 0);
}

void add_piece(char* board, int x, int y, char piece[PIECE_SIZE][PIECE_SIZE]) {
  for (int yy = 0; yy < PIECE_SIZE; ++yy)
    for (int xx = 0; xx < PIECE_SIZE; ++xx)
      if (piece[yy][xx]) put(board, x + xx, y + yy, 1);
}

int is_oob(char* board, int h, int x, int y, char piece[PIECE_SIZE][PIECE_SIZE]) {
  for (int yy = 0; yy < PIECE_SIZE; ++yy)
    for (int xx = 0; xx < PIECE_SIZE; ++xx)
      if (piece[yy][xx])
        if (x + xx < 0 || x + xx >= BOARD_W || y + yy < 0 || y + yy >= h)
          return 1;
  return 0;
}

int collides_with_board(char* board, int x, int y, char piece[PIECE_SIZE][PIECE_SIZE]) {
  for (int yy = 0; yy < PIECE_SIZE; ++yy)
    for (int xx = 0; xx < PIECE_SIZE; ++xx)
      if (piece[yy][xx] && is_solid(board, x + xx, y + yy))
        return 1;
  return 0;
}

void remove_filled_line(char* board, int h) {
  for (int y = 0; y < h; ++y) {
    int pos = (y * BOARD_W) / 8;
    if ((unsigned char)board[pos] == 0xff && (unsigned char)board[pos+1] == 0xff) {
      for (int yy = y; yy > 0; --yy) {
        int pos = (yy * BOARD_W) / 8;
        board[pos] = board[pos-2];
        board[pos+1] = board[pos-1];
      }
      board[0] = board[1] = 0;
      y = -1; // Look for more lines
      continue;
    }
  }
}

void update_screen(struct BoardState* s) {
  int board_x = (W - BOARD_W) / 2;
  int board_y = H - s->board_h;
  int offs = 0;
  while (s->piece_y - offs + 4 >= H) offs += H/2;
  for (int x = 0; x < W; ++x) {
    for (int y = 0; y < H; ++y) {
      int px = WALL;
      if (x >= board_x && x < board_x + BOARD_W && y >= board_y + offs) {
        px = is_solid(s->board, x-board_x, s->board_h - (y-board_y-offs) - 1) ? PIECE : 0;
      }
      screen[y * W + x] = px;
    }
  }
}

void init();
void game_loop();

void play() {
  init();
  game_loop();
}

void win() {
  __asm__("nop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop\n\t");
  char* s = "\xaa\x55\xaa\xa9\x53\xee\x99\xba\xa9\x53\xa4\x55\xa0\x00\x00\x03\xfc\x00\x49\x20\x04\x02\x00\x46\x20\x08\x61\x01\x70\xe8\x2f\x9f\x42\xdf\xf4\x2f\xff\x43\xf9\xfc\x18\x01\x81\x00\x08\x08\x01\x00\x80\x10\x06\x06\x00\x1f\x80";
  for (int i = 0; i < W*H; ++i)
    screen[i] = (s[i/8] & (1<<(7-i%8))) ? 16 : 0;
  screen[266] = 12;
  for (int i = 0; i < 30; ++i) {
    putc(NOT_WON, stdout);
    fflush(stdout);
    process_cmds_until_tick();
  }
  putc(WON, stdout);
  fflush(stdout);
  exit(0);
}

void init() {
  // Uncompress tetris pieces
  for (int i = 0; i < 40; ++i)
    for (int j = 0; j < 8; ++j)
      ((char*)pieces)[i*8+j] = (comp_pieces[i] & (1 << (7-j))) != 0;
  srand(737415);
}

void game_loop() {
  struct BoardState s = {};
  s.piece_x = 4;
  s.piece_y = 0;
  s.piece = rand() % PIECE_COUNT;
  s.rot = rand() % ROT_COUNT;
  s.board_h = 16;
  s.prev_x = 0;
  s.prev_y = 0;
  memset(s.board, 0, BOARD_W*2);
  add_piece(s.board, s.piece_x, s.piece_y, pieces[s.piece][s.rot]);
  update_screen(&s);

  while (1) {
    process_cmds_until_tick();

    s.prev_x = (char)s.piece_x;
    s.prev_y = (char)s.piece_y;
    if (space_pressed && !prev_space_pressed) {
      // Rotate
      remove_piece(s.board, s.prev_x, s.prev_y, pieces[s.piece][s.rot]);
      s.rot = (s.rot + 1) % ROT_COUNT;
      if (collides_with_board(s.board, s.piece_x, s.piece_y, pieces[s.piece][s.rot])) {
        // Undo rotation
        s.rot = (s.rot - 1) % ROT_COUNT;
        add_piece(s.board, s.prev_x, s.prev_y, pieces[s.piece][s.rot]);
      } else {
        add_piece(s.board, s.prev_x, s.prev_y, pieces[s.piece][s.rot]);
        update_screen(&s);
      }
    }
    prev_space_pressed = (char)space_pressed;

    if (s.board_h > 1 && tics % 600 == 0) {
      --s.board_h;
    }

    if (tics % 5 == 0 && s_pressed) {
      ++s.piece_y;
    } else if (tics % 30 == 0) {
      ++s.piece_y;
    }
    if (tics % 10 == 1) {
      if (a_pressed)
        --s.piece_x;
      else if (d_pressed)
        ++s.piece_x;
    }
    if (s.prev_x != s.piece_x || s.prev_y != s.piece_y) {
      remove_piece(s.board, s.prev_x, s.prev_y, pieces[s.piece][s.rot]);
      if (is_oob(s.board, s.board_h, s.piece_x, s.piece_y, pieces[s.piece][s.rot])
          || collides_with_board(s.board, s.piece_x, s.piece_y, pieces[s.piece][s.rot])) {
        if (s.prev_y != s.piece_y) {
          // Reached ground. Keep piece here and send a new one
          add_piece(s.board, s.prev_x, s.prev_y, pieces[s.piece][s.rot]);
          remove_filled_line(s.board, s.board_h);
          s.piece = rand() % PIECE_COUNT;
          s.rot = rand() % ROT_COUNT;
          s.piece_x = 4;
          s.piece_y = 0;
          // If we still collide with something we lost
          if (collides_with_board(s.board, s.piece_x, s.piece_y, pieces[s.piece][s.rot]))
            return;
        } else {
          // Hit a wall, undo movement
          s.piece_x = s.prev_x;
          s.piece_y = s.prev_y;
        }
      }
      add_piece(s.board, s.piece_x, s.piece_y, pieces[s.piece][s.rot]);
      update_screen(&s);
    }

    // There's no win condition
    // YOU CAN ONLY LOSE, BWA-HA-HA!
    putc(NOT_WON, stdout);
    fflush(stdout);
  }
}

int main(int argc, char **argv) {
  printf("%c%c%c%c", W, H, TW, TH);
  fflush(stdout);
  play();
  return 0;
}
