/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ECB 1
#define CBC 0
#define CTR 0
#include "aes.h"
#include "raylib.h"
#include "sha256.h"

#include "spritesheet.h"

/*
 * TODO:
 * - Do we need diameter in the asteroid struct?
 * - Make speed independent of frame rate
 * - Isn't it easier to make SCREEN_* float and cast in ones at initialization
 *   than many times to (float)?
 * - More economical memory for projectiles and shards?
 * - Seed asteroid sizes with the radius rather than the diameter?
 */

uint8_t g_flag[] = "\x17\x10\x45\x5d\x8e\x84\xda\x7d\x2b\x7e\xa8\x0f\x94\x3c\xcb\x0f"
                "\xe3\x1c\xb1\x50\xfb\xd5\x6c\x1c\x51\x7b\xca\xf2\x54\x08\x33\x8d";
#define FLAG_SIZE 32

void decrypt(uint8_t* key, uint8_t* data) {
  struct AES_ctx ctx;
  AES_init_ctx(&ctx, key);
  AES_ECB_decrypt(&ctx, data);
}

#define SCREEN_WIDTH  800
#define SCREEN_HEIGHT 600
#define SCREEN_CENTER_X SCREEN_WIDTH/2
#define SCREEN_CENTER_Y SCREEN_HEIGHT/2

#define FONT_SIZE 30
#define SUBSCRIPT_SIZE 16
#define TEXT_GAME_OVER "GAME OVER"
#define TEXT_TIMES_UP  "TIME'S UP"

// All asteroid sprites are square, this indicates the side
// of said squre. It will also dub as radius of the circular
// hit box.
#define ASTEROID_SIZE_BIG 200.0f
#define ASTEROID_SIZE_MEDIUM 130.0f
#define ASTEROID_SIZE_SMALL 70.0f

// Y coordinate in the spritehsheet.
#define Y_BIG 0.0f
#define Y_MEDIUM ASTEROID_SIZE_BIG
#define Y_SMALL ASTEROID_SIZE_BIG + ASTEROID_SIZE_MEDIUM

#define MAX_ASTEROIDS 1000
#define N_SHAPES_BIG 3
#define N_SHAPES_MEDIUM 4
#define N_SHAPES_SMALL 8

#define ASTEROID_ROTATION_SPEED_MIN 1
#define ASTEROID_ROTATION_SPEED_MAX 20
#define ASTEROID_ROTATION_SPEED_DELTA ASTEROID_ROTATION_SPEED_MAX - ASTEROID_ROTATION_SPEED_MIN
#define ASTEROID_ROTATION_UNIT 0.05f

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

Color g_asteroid_colors[] = {
  { 75, 250, 55, 255 },
  { 55, 250, 245, 255 },
  { 100, 85, 255, 255 },
  { 200, 85, 255, 255 }
};

typedef enum {
  ASTEROID_BIG = 0,
  ASTEROID_MEDIUM = 1,
  ASTEROID_SMALL = 2
} AsteroidType;

typedef struct {
  Vector2 origin;
  AsteroidType type;
  float diameter;
  float radius;
  float sprite_ypos; // Y-coordinate of in the sprite sheet
  int min_speed;
  int max_speed;
  int n_shapes;  // Number of variations in the sprite sheet
  int initial_health;
} AsteroidConfig;

AsteroidConfig g_config_big = {
  .origin = (Vector2){ASTEROID_SIZE_BIG/2, ASTEROID_SIZE_BIG/2},
  .type = ASTEROID_BIG,
  .diameter = ASTEROID_SIZE_BIG,
  .radius = ASTEROID_SIZE_BIG/2,
  .sprite_ypos = Y_BIG,
  .min_speed = 1,
  .max_speed = 3,
  .n_shapes = N_SHAPES_BIG,
  .initial_health = 5
};

AsteroidConfig g_config_medium = {
  .origin = (Vector2){ASTEROID_SIZE_MEDIUM/2, ASTEROID_SIZE_MEDIUM/2},
  .type = ASTEROID_MEDIUM,
  .diameter = ASTEROID_SIZE_MEDIUM,
  .radius = ASTEROID_SIZE_MEDIUM/2,
  .sprite_ypos = Y_MEDIUM,
  .min_speed = 1,
  .max_speed = 4,
  .n_shapes = N_SHAPES_MEDIUM,
  .initial_health = 3
};

AsteroidConfig g_config_small = {
  .origin = (Vector2){ASTEROID_SIZE_SMALL/2, ASTEROID_SIZE_SMALL/2},
  .type = ASTEROID_SMALL,
  .diameter = ASTEROID_SIZE_SMALL,
  .radius = ASTEROID_SIZE_SMALL/2,
  .sprite_ypos = Y_SMALL,
  .min_speed = 1,
  .max_speed = 4,
  .n_shapes = N_SHAPES_SMALL,
  .initial_health = 1
};

// Because we'll be rendering asteroids every frame @ 60 fps
// but initialize them much less frequent than that, we should
// put as many properties that will save us time rendering as
// possible.
typedef struct {
  Color color;
  Vector2 origin;
  float x;
  float y;
  float speedx;
  float speedy;
  float diameter;
  float radius;
  float rotation;
  float rotation_speed;
  Rectangle sprite_rectangle;
  AsteroidType type;
  int health;
  int age;  // How many frames have it been onscreen
} Asteroid;

#define PLAYER_SPRITE_WIDTH 65.0f
#define PLAYER_SPRITE_HEIGHT 50.0f
#define PLAYER_SPRITE_RECT (Rectangle){0.0f, 400.0f, PLAYER_SPRITE_WIDTH, PLAYER_SPRITE_HEIGHT}

#define PLAYER_WIDTH 50.0f
#define PLAYER_HEIGHT 40.0f

#define PLAYER_RADIUS 0.5f * PLAYER_HEIGHT  // For collision detction
#define PLAYER_ORIGIN (Vector2){PLAYER_WIDTH * .3f, PLAYER_HEIGHT/2}


#define PLAYER_ROTATION_SPEED 5.0f
#define PLAYER_MAX_SPEED 6.0f
#define PLAYER_ACCELERATION 0.06f
#define PLAYER_DECEL 0.008f

typedef struct {
  float x;
  float y;
  float speed;
  int rotation;
  bool destruction_animation;
} Player;

typedef struct {
  double t0;
  float x;
  float y;
  float speedx;
  float speedy;
  bool active;
} Projectile;

#define PROJECTILE_SPEED 8.0f
#define PROJECTILE_DELAY 0.20  // double
#define PROJECTILE_LIFETIME 2.0 // double
#define N_PROJECTILES 15
#define PROJECTILE_DIAMETER 2
#define PROJECTILE_RADIUS PROJECTILE_DIAMETER / 2

#define N_SHARDS 10
#define SHARD_DISTANCE 4.0f
#define SHARD_SPEED 12.0f


typedef struct PoolFreeNode PoolFreeNode;
struct PoolFreeNode {
  PoolFreeNode *next;
};

typedef struct {
  void *buf;
  size_t buf_len;
  PoolFreeNode *head;
} Pool;

void pool_free(Pool *pool, Asteroid *ptr) {
  PoolFreeNode *node = (PoolFreeNode*)ptr;
  node->next = pool->head;
  pool->head = node;
}

void pool_free_all(Pool *pool) {
  for(size_t i = 0; i < MAX_ASTEROIDS; ++i) {
    PoolFreeNode *node = (PoolFreeNode *)(pool->buf + i * sizeof(Asteroid));
    node->next = pool->head;
    pool->head = node;
  }
}

Pool *pool_init(Pool *pool) {
  size_t back_buf_len = MAX_ASTEROIDS * sizeof(Asteroid);
  void *back_buf = malloc(back_buf_len);
  if (back_buf == NULL) {
    perror("Backing buffer allocation failure");
    exit(EXIT_FAILURE);
  }

  pool->buf = back_buf;
  pool->buf_len = back_buf_len;

  pool_free_all(pool);
  return pool;
}

Asteroid *pool_alloc(Pool *pool) {
  PoolFreeNode *node = pool->head;
  if (node == NULL) {
    fprintf(stderr, "Pool allocator exhausted\n");
    exit(EXIT_FAILURE);
  }

  pool->head = node->next;
  return (Asteroid*)node;
}

typedef struct {
  Asteroid* array[MAX_ASTEROIDS];
  size_t size;
} ActiveAsteroids;

ActiveAsteroids* init_active_asteroids_array(void) {
  ActiveAsteroids* active_asteroids = (ActiveAsteroids*)malloc(sizeof(ActiveAsteroids));
  if (active_asteroids == NULL) {
    perror("Couldn't allocate ActiveAsteroids\n");
    exit(EXIT_FAILURE);
  }
  return active_asteroids;
}

typedef struct {
  uint64_t color_sum;  // sum of colors of destroyed asteroids
  uint8_t small_asteroids_destroyed;
  uint8_t projectiles;
  uint8_t asteroid_hits;
} ProofOfPlay;

#define FRAMES_TO_BLOCK 300
#define FRAME_LIMIT 8 * FRAMES_TO_BLOCK
#define BLOCK_SIZE 7

typedef struct {
  bool game_over;
  uint64_t frame_counter;
  Pool *pool;
  ActiveAsteroids *active_asteroids;
  Player *player;
  ProofOfPlay *pop;

  double current_time;
  double last_spawn_time;
  double last_shot_fired;

  Projectile projectiles[N_PROJECTILES];
  Projectile shards[N_SHARDS];  // explosion shards

  uint8_t flag[FLAG_SIZE];
} GameState;


void do_game_over(GameState* state) {
  state->game_over = true;
  state->player->destruction_animation = true;
}


void add_asteroid(ActiveAsteroids* active_asteroids, Asteroid* asteroid) {
  if (active_asteroids->size >= MAX_ASTEROIDS) {
    fprintf(stderr, "Number of active asteroids exceeds the maxiumum allowed number\n");
    exit(EXIT_FAILURE);
  }
  active_asteroids->array[active_asteroids->size] = asteroid;
  active_asteroids->size++;
}

void init_asteroid(AsteroidConfig *conf, Asteroid* asteroid, float x, float y, Color color, int age) {
  asteroid->type = conf->type;
  asteroid->color = color;
  asteroid->x = x;
  asteroid->y = y;
  asteroid->sprite_rectangle.x = (rand() % conf->n_shapes) * conf->diameter;
  asteroid->sprite_rectangle.y = conf->sprite_ypos;
  asteroid->sprite_rectangle.width = conf->diameter;
  asteroid->sprite_rectangle.height = conf->diameter;
  asteroid->diameter = conf->diameter;
  asteroid->radius = conf->radius;
  asteroid->origin = conf->origin;

  // Direction is chosen randomly, however we need to avoid
  // cardinal directions. Asteroids are spawned outside the screen,
  // let's say x = -width, then at a 90 degree angle the asteroid
  // never appears on-screen.
  float delta_half_arc = 10.0f;  // forbidden arc (in degrees) for segment
  float allowed_span = 90.0f - 2 * delta_half_arc;
  float offset_in_segment = allowed_span * ((float)rand()/(float)RAND_MAX);
  int segment = rand() % 4;
  float angle = (float)segment * 90.0f + delta_half_arc + offset_in_segment;
  angle *= DEG2RAD;

  float real_speed = (float)(rand() % (conf->max_speed - conf->min_speed) + conf->min_speed);
  asteroid->speedx = cosf(angle) * real_speed;
  asteroid->speedy = sinf(angle) * real_speed;

  float rotation_direction = (rand() % 100) < 50 ? 1.0f : -1.0f;
  asteroid->rotation = (float)(rand() % 360) * rotation_direction;
  asteroid->rotation_speed = (float)(ASTEROID_ROTATION_SPEED_MIN + (rand() % ASTEROID_ROTATION_SPEED_DELTA)) * ASTEROID_ROTATION_UNIT * rotation_direction;

  asteroid->health = conf->initial_health;
  asteroid->age = age;
}


void spawn_asteroid(GameState *state, AsteroidConfig *config, float x, float y, Color color, int age) {
  Asteroid *asteroid = pool_alloc(state->pool);
  init_asteroid(config, asteroid, x, y, color, age);
  add_asteroid(state->active_asteroids, asteroid);
}


void spawn_big_asteroid(GameState *state) {
  float x = (float)(rand() % SCREEN_WIDTH);
  float y = (float)(rand() % SCREEN_HEIGHT);

  switch(rand() % 4) {
    case 0:  // Top of the screen
      y = -g_config_big.radius;
      break;
    case 1:  // Right of the screen
      x = (float)SCREEN_WIDTH + g_config_big.radius;
      break;
    case 2:  // Bottom of the screen
      y = (float)SCREEN_HEIGHT + g_config_big.radius;
      break;
    case 3:  // Left of the screen
      x = -g_config_big.radius;
      break;
  }
  Color color = g_asteroid_colors[
    rand() % ARRAY_SIZE(g_asteroid_colors)];
  spawn_asteroid(state, &g_config_big, x, y, color, 0);
}

void split_asteroid(GameState *state, AsteroidConfig *config, Asteroid *asteroid) {
  for (int i = 0; i < 2; ++i) {
    spawn_asteroid(state, config, asteroid->x, asteroid->y, asteroid->color, asteroid->age);
  }
}

void update_asteroids(GameState *state) {

  for (size_t i = 0; i < state->active_asteroids->size; ++i) {
    Asteroid *asteroid = state->active_asteroids->array[i];
    asteroid->x += asteroid->speedx;
    asteroid->y += asteroid->speedy;

    if (asteroid->x > (float)SCREEN_WIDTH + asteroid->radius) {
      asteroid->x = -asteroid->radius;
    }

    if (asteroid->y > (float)SCREEN_HEIGHT + asteroid->radius) {
      asteroid->y = -asteroid->radius;
    }

    if (asteroid->x < -asteroid->radius) {
      asteroid->x = (float)SCREEN_WIDTH + asteroid->radius;
    }

    if (asteroid->y < -asteroid->radius) {
      asteroid->y = (float)SCREEN_HEIGHT + asteroid->radius;
    }

    asteroid->rotation += asteroid->rotation_speed;

    bool hit_player = CheckCollisionCircles(
        (Vector2){asteroid->x, asteroid->y}, asteroid->radius,
        (Vector2){state->player->x, state->player->y}, PLAYER_RADIUS);

    if (hit_player) {
      do_game_over(state);
    }
    asteroid->age++;
  }
}

void update_spaceship_and_projectiles(GameState *state) {
  Player *player = state->player;

  if (IsKeyDown(KEY_RIGHT) || IsKeyDown(KEY_D)) {
    player->rotation += PLAYER_ROTATION_SPEED;
  }

  if (IsKeyDown(KEY_LEFT) || IsKeyDown(KEY_A)) {
    player->rotation -= PLAYER_ROTATION_SPEED;
  }

  if (IsKeyDown(KEY_UP) || IsKeyDown(KEY_W)) {
    if (player->speed < PLAYER_MAX_SPEED) {
      player->speed += PLAYER_ACCELERATION;
    } else {
      player->speed = PLAYER_MAX_SPEED;
    }
  }

  if (IsKeyDown(KEY_DOWN) || IsKeyDown(KEY_S)) {
    if (player->speed > 0.0f) {
      player->speed -= PLAYER_ACCELERATION;
    } else {
      player->speed = 0.0f;
    }
  }
  float player_cos = cosf(player->rotation * DEG2RAD);
  float player_sin = sinf(player->rotation * DEG2RAD);

  float player_length_x = PLAYER_WIDTH * player_cos;
  float player_length_y = PLAYER_WIDTH * player_sin;

  float player_length_x_abs = fabs(player_length_x);
  float player_length_y_abs = fabs(player_length_y);

  player->x += player->speed * player_cos;
  player->y += player->speed * player_sin;
  player->speed *= 0.9999;

  if (player->x > (float)SCREEN_WIDTH + player_length_x_abs) {
    player->x = -player_length_x_abs;
  }

  if (player->x < -player_length_x_abs) {
    player->x = (float)SCREEN_WIDTH + player_length_x_abs;
  }

  if (player->y > (float)SCREEN_HEIGHT + player_length_y_abs) {
    player->y = -player_length_y_abs;
  }

  if (player->y < -player_length_y_abs) {
    player->y = (float)SCREEN_HEIGHT + player_length_y_abs;
  }

  // Projectiles
  if (IsKeyPressed(KEY_SPACE)) {
    if (state->current_time - state->last_shot_fired > PROJECTILE_DELAY) {
      // TODO: could this be done better?
      bool found = false;
      for (int i = 0; i < N_PROJECTILES; ++i) {
        Projectile *projectile = &state->projectiles[i];
        if (!projectile->active) {
          projectile->active = true;
          projectile->t0 = state->current_time;
          projectile->x = player->x + player_length_x;
          projectile->y = player->y + player_length_y;
          projectile->speedx = player_cos * PROJECTILE_SPEED;
          projectile->speedy = player_sin * PROJECTILE_SPEED;
          found = true;
          break;
        }
      }
      if (found) {
        state->last_shot_fired = state->current_time;
        state->pop->projectiles++;

      }
    }
  }
}

void update_asteroid_hits(GameState *state) {
  for (int i = 0; i < N_PROJECTILES; ++i) {
    Projectile *projectile = &state->projectiles[i];
    if (projectile->active) {
      projectile->x += projectile->speedx;
      projectile->y += projectile->speedy;

      for (int j = state->active_asteroids->size - 1; j >= 0; --j) {
        Asteroid *asteroid = state->active_asteroids->array[j];
        if (CheckCollisionCircles(
                (Vector2){projectile->x, projectile->y},
                PROJECTILE_RADIUS,
                (Vector2){asteroid->x, asteroid->y},
                asteroid->radius)) {
          asteroid->health--;
          state->pop->asteroid_hits++;
          projectile->active = false;
          if (asteroid->health <= 0) {
            if (asteroid->type == ASTEROID_BIG) {

              split_asteroid(state, &g_config_medium, asteroid);
          
            } else if (asteroid->type == ASTEROID_MEDIUM) {

              split_asteroid(state, &g_config_small, asteroid);
              
            } else {
              // Small asteroid destroyed
              Color color = asteroid->color;
              state->pop->color_sum += ((color.r<<16)|(color.g<<8)|(color.b));
              state->pop->small_asteroids_destroyed++;
            }
            int last_idx = state->active_asteroids->size - 1;
            state->active_asteroids->array[j] = state->active_asteroids->array[last_idx];
            state->active_asteroids->array[last_idx] = NULL;
            state->active_asteroids->size--;
            pool_free(state->pool, asteroid);
          }
        }
      }

      if (projectile->active && (state->current_time - projectile->t0 > PROJECTILE_LIFETIME)) {
        projectile->active = false;
      }
    }
  }
}

void update_explosion(GameState *state) {
  if (state->player->destruction_animation) {
    for (int i = 0; i < N_SHARDS; ++i) {
      Projectile *shard = &state->shards[i];
      if (!shard->active) {
        float arc = 2 * PI * i /(float)N_SHARDS;
        float shard_cos = cosf(arc);
        float shard_sin = sinf(arc);
        shard->x = state->player->x + SHARD_DISTANCE * shard_cos;
        shard->y = state->player->y + SHARD_DISTANCE * shard_sin;
        shard->speedx = SHARD_SPEED * shard_cos;
        shard->speedy = SHARD_SPEED * shard_sin;
        shard->active = true;
      } else {
        shard->x += shard->speedx;
        shard->y += shard->speedy;
      }

      if ((shard->x > (float)SCREEN_WIDTH || shard->x < 0) &&
          (shard->y > (float)SCREEN_HEIGHT || shard->y < 0)) {
        state->player->destruction_animation = false;
      }
    }
  }
}

void draw_game(GameState *state, Texture2D spritesheet) {
  for (size_t i = 0; i < state->active_asteroids->size; ++i) {
    Asteroid *asteroid = state->active_asteroids->array[i];

    DrawTexturePro(
      spritesheet,
      asteroid->sprite_rectangle,
      (Rectangle){asteroid->x, asteroid->y, asteroid->diameter, asteroid->diameter},
      asteroid->origin,
      asteroid->rotation,
      asteroid->color);
  }

  for(int i = 0; i < N_PROJECTILES; ++i) {
    Projectile *projectile = &state->projectiles[i];
    if (projectile->active) {
      DrawCircle(projectile->x, projectile->y, PROJECTILE_DIAMETER, WHITE);
    }
  }

  if (!state->game_over) {
    // Raylib's rotation functions use degrees, not radians
    DrawTexturePro(
        spritesheet,
        PLAYER_SPRITE_RECT,
        (Rectangle){state->player->x, state->player->y, PLAYER_WIDTH, PLAYER_HEIGHT},
        PLAYER_ORIGIN,
        state->player->rotation,
        WHITE);
  }

  if (state->player->destruction_animation) {
    for (int i = 0; i < N_SHARDS; ++i) {
      DrawCircle(state->shards[i].x, state->shards[i].y, SHARD_DISTANCE, ORANGE);
    }
  }
}

void draw_ui(GameState *state) {
  float width;

  if (state->game_over) {
    int text_width;
    char *text;

    if (state->frame_counter < FRAME_LIMIT) {
      text_width = MeasureText(TEXT_GAME_OVER, FONT_SIZE);
      text = TEXT_GAME_OVER;
    } else {
      text_width = MeasureText(TEXT_TIMES_UP, FONT_SIZE);
      text = TEXT_TIMES_UP;
    }
    DrawText(text, (float)SCREEN_CENTER_X - text_width/2, (float)SCREEN_CENTER_Y, FONT_SIZE, ORANGE);

    if (*(uint32_t*)state->flag == 0x7b465443 && state->flag[31] == '}') {
      char flag_text[50] = {};
      memcpy(flag_text, state->flag, FLAG_SIZE);
      text_width = MeasureText(flag_text, SUBSCRIPT_SIZE);
      DrawText(flag_text, (float)SCREEN_CENTER_X - text_width/2, (float)SCREEN_CENTER_Y + FONT_SIZE, SUBSCRIPT_SIZE, RED);
    }

  } 

  float dx = ((float)FRAME_LIMIT / (float)SCREEN_WIDTH);
  width = (float)(FRAME_LIMIT - state->frame_counter) / dx;

  DrawRectangle(0, 0, width, 6, RED);
  
  // TODO: display flag if one is found
}

void update_proof_of_play(GameState *state) {

  if (state->frame_counter % FRAMES_TO_BLOCK == 0) {
    uint8_t block[BLOCK_SIZE] = {};

    block[0] = state->pop->small_asteroids_destroyed;
    block[1] = state->pop->projectiles;
    block[2] = state->pop->asteroid_hits;
    *(uint32_t*)&block[3] = state->pop->color_sum;

    uint8_t digest[SHA256_DIGEST_SIZE] = {};
    SHA256_hash(block, BLOCK_SIZE, digest);

    memcpy(state->flag, g_flag, FLAG_SIZE);

    decrypt(digest, state->flag);
    decrypt(&digest[AES_BLOCKLEN], &state->flag[AES_BLOCKLEN]);

#ifdef DEBUG
    printf("DSTR: 0x%x\n", state->pop->small_asteroids_destroyed);
    printf("PROJ: 0x%x\n", state->pop->projectiles);
    printf("HITS: 0x%x\n", state->pop->asteroid_hits);
    printf("COL : 0x%lx\n", state->pop->color_sum);

    for (int i = 0; i < BLOCK_SIZE; ++i) {
      printf(" %02x", block[i]);
    }
    printf("\n");
    printf("[%2d] ", (uint32_t)(state->frame_counter/FRAMES_TO_BLOCK));
    
    for (int i = 0; i < SHA256_DIGEST_SIZE; ++i) {
      printf("%02x", digest[i]);
    }
    printf("\n");
#endif
  }
}

void reset(GameState *state) {
  state->game_over = false;

  state->player->x = SCREEN_CENTER_X;
  state->player->y = SCREEN_CENTER_Y;
  state->player->rotation = (float)(rand() % 360);
  state->player->destruction_animation = false;
  state->player->speed = 0;

  state->last_spawn_time = GetTime();
  state->last_shot_fired = GetTime();

  state->frame_counter = 0;

  memset(state->pop, 0, sizeof(ProofOfPlay));
  memset(state->active_asteroids, 0, sizeof(ActiveAsteroids));
  pool_free_all(state->pool);

  memset(state->projectiles, 0, sizeof(state->projectiles));
  memset(state->shards, 0, sizeof(state->shards));
  
}

int main(void) {

  srand(time(NULL));

  Player player = {};
  ProofOfPlay pop = {};
  Pool pool;

  GameState state = {
    .game_over = false,
    .pool = pool_init(&pool),
    .active_asteroids = init_active_asteroids_array(),
    .player = &player,
    .pop = &pop,
  };

  reset(&state);

  SetConfigFlags(FLAG_MSAA_4X_HINT); // Enable 4x Multisample Anti-Aliasing
  InitWindow(SCREEN_WIDTH, SCREEN_HEIGHT, "Asteroids Redux");

  Image img = LoadImageFromMemory(".png", spritesheet_png, spritesheet_png_len);
  if (!IsImageValid(img)) {
    fprintf(stderr, "Image is not valid\n");
  }
  // Note: textures must be loaded after initialzation.
  Texture2D spritesheet = LoadTextureFromImage(img);
  if(!IsTextureValid(spritesheet)) {
    fprintf(stderr, "Spritesheet texture is not valid\n");
    exit(EXIT_FAILURE);
  }
  // Further improve anti-aliasing for rotating sprites
  SetTextureFilter(spritesheet, TEXTURE_FILTER_BILINEAR);


  SetTargetFPS(60);
  while (!WindowShouldClose()) {
    BeginDrawing();
    ClearBackground(BLACK);
    
    state.current_time = GetTime();

    // Asteroid spwan logic
    // Spawn every N seconds.
    if (!state.game_over) {
      state.frame_counter++;
      if (state.frame_counter > FRAME_LIMIT) {
        // state.frame_counter = 0;
        do_game_over(&state);
      }

      update_proof_of_play(&state);
      if (state.current_time - state.last_spawn_time > 5) {
        spawn_big_asteroid(&state);
        state.last_spawn_time = state.current_time;
      }
      update_spaceship_and_projectiles(&state);
    }


    update_asteroids(&state);
    update_asteroid_hits(&state);
    

    if (state.game_over) {
      update_explosion(&state);
      if (IsKeyPressed(KEY_R)) {
        reset(&state);
      }
    }


    // Rendering
    draw_game(&state, spritesheet);
    draw_ui(&state);

    EndDrawing();
  }

  return 0;
}
