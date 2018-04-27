// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.



// Note: This code isn't nice, isn't written according to any style guide, etc.
// It was basically written in two evenings to be an example client for a CTF,
// so there are A LOT of nasty hacks all around and unhandled edge cases.
// Look at it on your own risk. You have been warned.
// Hmm, though this would make a great anti-example on how to write code.
// Gynvael

#include <math.h>
#include <SDL2/SDL.h>
#include "common.h"

#undef main

// Global variables. A lot of them. Don't look.

#define IMPORT_DATA_AS_STRING(str_name, symbol_name) \
  extern "C" char symbol_name ## _start; \
  extern "C" char symbol_name ##_end; \
  const std::string str_name( \
    &symbol_name ## _start, \
    &symbol_name ## _end - &symbol_name ## _start)

IMPORT_DATA_AS_STRING(sky_bitmap, _binary_sky_palette_raw);
IMPORT_DATA_AS_STRING(font_bitmap, _binary_font_cc0_mold_asalga_raw);

SDL_atomic_t the_end{};

// Access to these should probably be synchronized. It's not.
const char *server;
SDL_Surface *framebuffer;

int gAngle = 90;
int gPower = 50;
int gWeapon = 1;
bool gReadyToFire;
NetSock *gClient;

double gNow;   // Timer;
double gDiff;  // Difference from last frame;

double gLastFall;
bool gGroundFall;

Tank gTanks[2]{};

// Drawing stuff.
bool gRedrawTargetingDataBar;

uint8_t gGameMap[MAP_W * MAP_H / 8];
bool gRedrawMap;
SDL_Surface *gMapSurface;

SDL_mutex *gDrawTextMutex;
std::string gDrawTextTop;
std::string gDrawTextBottom;

struct ExplosionState {
  bool in_progress;
  int x, y;  // Epicenter.
  int r;  // Explosion radius.
  int weapon;
  double progress;  // Animation progress.
};

SDL_mutex *gDrawBulletMutex;
bool gBulletAnimationInProgress;
std::vector<BulletEvent> gBullet[2];
double gBulletIdx[2];
ExplosionState gExplosion[2];

inline bool FontBitSet(int x, int y, char ch) {
  uint8_t *font = (uint8_t*)font_bitmap.data();
  int font_x = (ch % 8) * 16;
  int font_y = ((ch - 0x20) / 8) * 16;

  if (x < 0 || y < 0 || x >= 16 || y >= 16) {
    return false;
  }

  return font[font_x + x + (font_y + y) * 128];
}

void PrintChar(int x, int y, char ch, bool color_variant) {
  if (ch < ' ' || ch > '~') {
    return;
  }

  uint8_t *px = (uint8_t*)framebuffer->pixels;

  for (int j = -1; j < 17; j++) {
    for (int i = -1; i < 17; i++) {
      if (FontBitSet(i, j, ch) != 0) {
        int px_idx = (y + j) * framebuffer->pitch +
                     (x + i) * framebuffer->format->BytesPerPixel;

        if (color_variant) {
          px[px_idx + 2] = 255;
          px[px_idx + 1] = j * 16;
          px[px_idx + 0] = 0;
        } else {
          px[px_idx + 2] = 0;
          px[px_idx + 1] = j * 16;
          px[px_idx + 0] = 255;
        }
        continue;
      }

      // Outline perhaps?
      // P.S. Yes, I am aware there are 10 better ways to implement this.
      // But this doesn't really matter in a CTF task ;)
      struct { int vx, vy; } outline[] = {
        {  0, -1 },
        {  0,  1 },
        {  1,  0 },
        { -1,  0 }
      };

      for (int k = 0; k < 4; k++) {
        if (FontBitSet(i + outline[k].vx, j + outline[k].vy, ch) != 0) {
          int px_idx = (y + j) * framebuffer->pitch +
                       (x + i) * framebuffer->format->BytesPerPixel;
          if (color_variant) {
            px[px_idx + 2] = (j + 2) * 8;
            px[px_idx + 1] = (j + 2) * 4;
            px[px_idx + 0] = 0;
          } else {
            px[px_idx + 2] = 0;
            px[px_idx + 1] = (j + 2) * 4;
            px[px_idx + 0] = (j + 2) * 8;
          }
          break;
        }
      }
    }
  }
}

void PrintString(int x, int y, const std::string& s, bool color_variant) {
  for (size_t i = 0; i < s.size(); i++) {
    PrintChar(x + i * 16, y, s.c_str()[i], color_variant);
  }
}

void PrintTop(const std::string& s) {
  uint8_t *px = (uint8_t*)framebuffer->pixels;
  memset(px, 0, 20 * framebuffer->pitch);
  PrintString(4, 2, s, true);
}

void PrintBottom(const std::string& s) {
  uint8_t *px = (uint8_t*)framebuffer->pixels;
  int px_idx = 500 * framebuffer->pitch;
  memset(px + px_idx, 0, 20 * framebuffer->pitch);

  PrintString(4, 502, s, false);
}

void PrintBottomHi(const std::string& s) {
  PrintString(4, 502, s, true);
}

void PrintBar() {
  // 39 characters.
  PrintBottom(  "Angle      *  Power     *  Weapon 1 2 3");

  char values[64]{};
  sprintf(values, "      %3i           %2i            %s %s %s",
      gAngle, gPower,
      gWeapon == 1 ? "1" : " ",
      gWeapon == 2 ? "2" : " ",
      gWeapon == 3 ? "3" : " ");

  PrintBottomHi(values);
}

void DrawTank(int tank_id) {
  static char tank_gfx[] =
    "...###..."  /* 9 x 4 */
    "$#######$"
    "#########"
    ".#$#$#$#.";
  //     ^ tank's x,y is in this spot

  uint8_t colors[2][3] = {
    { 0, 0xff, 0 },
    { 0xff, 0, 0 }
  };

  uint8_t *px = (uint8_t*)framebuffer->pixels;
  int idx = 0;
  for (int j = -3; j < 1; j++) {
    for (int i = -4; i < 5; i++, idx++) {
      if (tank_gfx[idx] == '.') {
        continue;
      }

      int mod = (tank_gfx[idx] == '#') ? 0 : 1;
      int px_idx = (gTanks[tank_id].y + j + 20) * framebuffer->pitch +
                   (gTanks[tank_id].x + i) * framebuffer->format->BytesPerPixel;
      px[px_idx + 2] = colors[tank_id][0] >> mod;
      px[px_idx + 1] = colors[tank_id][1] >> mod;
      px[px_idx + 0] = colors[tank_id][2] >> mod;
    }
  }
}

void RedrawMap() {
  // Render map.
  uint8_t *px = (uint8_t*)gMapSurface->pixels;
  uint8_t *sky_palette = (uint8_t*)sky_bitmap.data();
  for (int j = 0; j < MAP_H; j++) {
    for (int i = 0; i < MAP_W; i++) {
      int idx = i + j * MAP_W;
      int idx_byte = idx / 8;
      int idx_bit = idx % 8;

      int r, g, b;
      r = sky_palette[j * 3 + 0];
      g = sky_palette[j * 3 + 1];
      b = sky_palette[j * 3 + 2];

      if (((gGameMap[idx_byte] >> idx_bit) & 1)) {
        r = 44/2 + r / 8; // 44
        g = 35/2 + g / 8; // 35
        b = 24/2 + b / 8;
      }

      int px_idx = (j + 20) * gMapSurface->pitch +
                   i * gMapSurface->format->BytesPerPixel;
      px[px_idx + 0] = b;
      px[px_idx + 1] = g;
      px[px_idx + 2] = r;
    }
  }
}

void BulletRender(int tank_id) {
  std::vector<BulletEvent> *bullet_ev = &gBullet[tank_id];
  double idx = gBulletIdx[tank_id];

  if ((size_t)idx >= bullet_ev->size()) {
    bullet_ev->clear();
    return;
  }

  double end_idx = idx + gDiff * 200.0;  // Speed.

  size_t idx_i = (size_t)idx;
  size_t end_idx_i = std::min((size_t)end_idx, bullet_ev->size() - 1);

  int r = 6.0 + sin(gNow * 10.0) * 4.0;
  size_t diff = bullet_ev->size() - end_idx_i;
  if (diff < 200) {
    r = (double)r * ((diff - 150.0) / 50.0);
  } else if (diff < 150) {
    r = 0;
  }

  int r_sq = r * r;

  uint8_t *px = (uint8_t*)framebuffer->pixels;
  for (size_t i = idx_i; i <= end_idx_i; i++) {
    const auto& b = (*bullet_ev)[i];

    if (b.x < 0 || b.x >= MAP_W || b.y < 0 || b.y >= MAP_H) {
      continue;
    }

    for (int k = -r; k <= r; k++) {
      for (int l = -r; l <= r; l++) {

        if (k * k + l * l > r_sq) {
          continue;
        }

        int x = (int)b.x + l;
        int y = (int)b.y + k;

        if (x < 0 || x >= MAP_W || y < 0 || y >= MAP_H) {
          continue;
        }

        int px_idx = (y + 20) * framebuffer->pitch +
                     (x) * framebuffer->format->BytesPerPixel;
        px[px_idx + 2] = tank_id == 0 ? 0 : 255;
        px[px_idx + 1] = tank_id == 0 ? 255 : 0;
        px[px_idx + 0] = 0;
      }
    }
  }

  gBulletIdx[tank_id] = end_idx;

  if (end_idx_i == bullet_ev->size() - 1) {
    BulletEvent &ev = (*bullet_ev)[end_idx_i];

    gExplosion[tank_id] = ExplosionState{
        true,
        ev.x, ev.y,
        WEAPON_EXPLOSION_RADIUS[ev.weapon] + 1,
        ev.weapon,
        0.0
    };

    bullet_ev->clear();
    return;
  }
}

inline int GetPixel(uint8_t *px, uint32_t x, uint32_t y) {
  if (x >= MAP_W) {
    return -1;
  }

  if (y >= MAP_H) {
    return -1;
  }

  uint32_t idx = x + y * MAP_W;
  uint32_t idx_byte = idx / 8;
  uint32_t idx_bit = idx % 8;

  return (px[idx_byte] >> idx_bit) & 1;
}  

inline void PutPixel(uint8_t *px, uint32_t x, uint32_t y, int color) {
  if (x >= MAP_W) {
    return;
  }

  if (y >= MAP_H) {
    return;
  }

  uint32_t idx = x + y * MAP_W;
  uint32_t idx_byte = idx / 8;
  uint32_t idx_bit = idx % 8;

  uint8_t bit_mask = 1 << idx_bit;
  uint8_t bit_color = (color & 1) << idx_bit;

  px[idx_byte] &= ~bit_mask;
  px[idx_byte] |= bit_color;
}
 
// Make a slower function than this. Not possible? Huh.
bool ApplyGravitation(uint8_t *game_map) {
  if (gTanks[0].hp == 0 && gTanks[1].hp == 0) {
    return false;
  }

  bool fall = false;
  for (int i = 0; i < MAP_W; i++) {
    int y = MAP_H - 1;
    while (y >= 0 && GetPixel(game_map, i, y)) { y--; }
    while (y >= 0 && !GetPixel(game_map, i, y)) { y--; }

    while (y >= 0) {
      if (GetPixel(game_map, i, y)) {
        PutPixel(game_map, i, y, 0);

        int r = (rand() % 3) + 1;
        int j = 1;
        while (j < r && y + j < MAP_H && !GetPixel(game_map, i, y + j)) {
          j++;
        }

        PutPixel(game_map, i, y + j - 1, 1);
        fall = true;
      }

      y--;
    }
  }

  for (int i = 0; i < 2; i++) {
    if (gTanks[i].y < MAP_H - 1) {
      if (!GetPixel(game_map, gTanks[i].x, gTanks[i].y + 1)) {
        gTanks[i].y++;
        fall = true;
      }
    }
  }

  return fall;
}

void ApplyExplosionToMap(uint8_t *game_map, int x, int y, int weapon) {
  const int r = WEAPON_EXPLOSION_RADIUS[weapon];
  const int r_sq = r * r;
  const int effect = (weapon == 2) ? 1 : 0;  // Weapon 2 is a dirt bomb.
  for (int j = y - r; j <= y + r; j++) {
    for (int i = x - r; i <= x + r; i++) {
      if (j < 0 || j >= MAP_H || i < 0 || i >= MAP_W) {
        continue;
      }

      const int dx = i - x;
      const int dy = j - y;
      const int dist_sq = dx * dx + dy * dy;
      if (dist_sq > r_sq) {
        continue;
      }

      PutPixel(game_map, i, j, effect);
    }
  }
}

#define EXPLOSION_ANIM_TIME 0.75

void ExplosionRender(int tank_id) {
  ExplosionState &state = gExplosion[tank_id];
  state.progress += gDiff;
  if (state.progress > EXPLOSION_ANIM_TIME) {

    // Render the explotion to the gMapSurface.
    ApplyExplosionToMap(gGameMap, state.x, state.y, state.weapon);
    RedrawMap();
    state.in_progress = false;
    return;
  }

  uint8_t *px = (uint8_t*)framebuffer->pixels;
  int r_sq = (double)(state.r * state.r) *
             sin((state.progress / EXPLOSION_ANIM_TIME) * 1.570796);

  for (int k = -state.r; k <= state.r; k++) {
    for (int l = -state.r; l <= state.r; l++) {

      if (k * k + l * l > r_sq) {
        continue;
      }

      int x = (int)state.x + l;
      int y = (int)state.y + k;

      if (x < 0 || x >= MAP_W || y < 0 || y >= MAP_H) {
        continue;
      }

      int px_idx = (y + 20) * framebuffer->pitch +
                   (x) * framebuffer->format->BytesPerPixel;

      switch (state.weapon) {
        case 1:
          px[px_idx + 2] = 255 - rand() % 16;
          px[px_idx + 1] = 127 - rand() % 64;
          px[px_idx + 0] = 0;
          break;

        case 2:
          px[px_idx + 2] = 139 - rand() % 5;
          px[px_idx + 1] =  69 - rand() % 5;
          px[px_idx + 0] =  19 - rand() % 5;
          break;

        case 3:
          px[px_idx + 2] = 255 - rand() % 16;
          px[px_idx + 1] = 255 - rand() % 64;
          px[px_idx + 0] = 0;
          break;
      }
    }
  }

}

void HandleRendering() {
  if (gRedrawTargetingDataBar) {
    gRedrawTargetingDataBar = false;
    PrintBar();
  }

  if (gRedrawMap) {
    gRedrawMap = false;
    RedrawMap();
  }

  // Render map each frame.
  if (gLastFall < gNow - 0.01) {
    gGroundFall = ApplyGravitation(gGameMap);
    RedrawMap();
    gLastFall = gNow;
  }

  SDL_Rect map_region{0, 20, MAP_W, MAP_H};
  SDL_BlitSurface(gMapSurface, &map_region, framebuffer, &map_region);

  for (int i = 0; i < 2; i++) {
    if (gTanks[i].hp > 0) {
      DrawTank(i);
    }
  }

  // On demand render text.
  SDL_LockMutex(gDrawTextMutex);
  if (!gDrawTextTop.empty()) {
    PrintTop(gDrawTextTop);
    gDrawTextTop.clear();
  }

  if (!gDrawTextBottom.empty()) {
    PrintBottom(gDrawTextBottom);
    gDrawTextBottom.clear();
  }
  SDL_UnlockMutex(gDrawTextMutex);

  // Draw bullet and explosions.
  SDL_LockMutex(gDrawBulletMutex);
  bool both_empty = true;

  if (!gBullet[0].empty()) {  // A funny way to draw one anim after the other.
    both_empty = false;
    BulletRender(0);
  } else if (!gBullet[1].empty()) {
    both_empty = false;
    BulletRender(1);
  }

  //bool any_expl = false;
  for (int i = 0; i < 2; i++) {  
    if (gExplosion[i].in_progress) {
      ExplosionRender(i);
    }  

    if (gExplosion[i].in_progress) {  // Might have changed.
      both_empty = false;
      //any_expl = true;
    }
  }


  gBulletAnimationInProgress = (both_empty == false);

  // Shaky screen nastyhack.
  // Note: Commented out. To shaky.
  /*if (any_expl) {
    int dy = -sin(gNow * 200.0) * 3;
    int dx = cos(gNow * 200.0) * 3;    

    SDL_Rect src_region{0, 20 + 5, MAP_W, MAP_H - 10};    
    SDL_Rect dst_region{0 + dx, 20 + dy + 5, MAP_W, MAP_H - 10};
    SDL_BlitSurface(framebuffer, &src_region, framebuffer, &dst_region);  
  }*/
  SDL_UnlockMutex(gDrawBulletMutex);

}

int NetThreadFunc(void *) {

  NetSock c;
  if (!c.Connect(server, 1337)) {
    puts("Failed to connect.");
    SDL_LockMutex(gDrawTextMutex);
    gDrawTextBottom = "Failed to connect.";
    SDL_UnlockMutex(gDrawTextMutex);
    //SDL_AtomicSet(&the_end, 1);
    return 1;
  }

  gClient = &c;

  puts("Connected!");

  SDL_LockMutex(gDrawTextMutex);
  gDrawTextBottom = "Connected!";
  SDL_UnlockMutex(gDrawTextMutex);

  SDL_Delay(1000);
  gRedrawTargetingDataBar = true;

  int bullet_tank_id = 0;

  while (SDL_AtomicGet(&the_end) == 0) {
    Packet p;
    if (!RecvPacket(&c, &p)) {
      gClient = nullptr;
      puts("Disconnected.");

      SDL_LockMutex(gDrawTextMutex);
      gDrawTextBottom = "Disconnected.";
      SDL_UnlockMutex(gDrawTextMutex);

      //SDL_AtomicSet(&the_end, 1);
      return 2;
    }

    if (p.type == "GMAP") {
      // Wait with handling this packet until all the animations stop
      // playing themselves out.
      // The animations are rather short, so it shouldn't cause any
      // network issues.
      for (;;) {
        bool done;
        SDL_LockMutex(gDrawBulletMutex);
        done = (gBulletAnimationInProgress == false && gGroundFall == false);
        SDL_UnlockMutex(gDrawBulletMutex);

        if (done) {
          break;
        }

        SDL_Delay(100);
      }

      memcpy(gGameMap, &p.data[0], sizeof(gGameMap));
      gRedrawMap = true;
      continue;
    }

    if (p.type == "TANK") {
      // TODO(gynvael): Add synchronization here. Otherwise the tanks might
      // "jump" in a weird way on race condition hit (not that it's too
      // probable).
      memcpy(&gTanks, p.data.data(), sizeof(Tank) * 2);

      if (gTanks[0].hp > 0) {
        gReadyToFire = true;
      }
      continue;
    }

    if (p.type == "TEXT") {
      SDL_LockMutex(gDrawTextMutex);
      gDrawTextTop = std::string((const char*)&p.data[0], p.data.size());
      printf("%s\n", gDrawTextTop.c_str());
      SDL_UnlockMutex(gDrawTextMutex);
    }

    if (p.type == "BLLT") {
      SDL_LockMutex(gDrawBulletMutex);
      gBullet[bullet_tank_id].resize(p.data.size() / sizeof(BulletEvent));
      memcpy(&gBullet[bullet_tank_id][0], &p.data[0], p.data.size());
      gBulletIdx[bullet_tank_id] = 0.0;  // Reset idx.
      bullet_tank_id = !bullet_tank_id;
      gBulletAnimationInProgress = true;
      SDL_UnlockMutex(gDrawBulletMutex);
    }
  }

  return 0;
}

// Hyperion Tank Game client
int main(int argc, char **argv) {
  NetSock::InitNetworking(); // Initialize WinSock

  if (argc != 2) {
    puts("usage: hyperion_client <ip>");
    return 1;
  }

  server = argv[1];

  if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER | SDL_INIT_EVENTS) != 0) {
    puts("SDL failed");
    return 3;
  }

  // Initialize all mutexes.
  gDrawTextMutex = SDL_CreateMutex();
  gDrawBulletMutex = SDL_CreateMutex();

  // Initialize timer.
  gNow = (double)SDL_GetTicks() / 1000.0;
  gDiff = 0.001;

  SDL_Window *win = SDL_CreateWindow(
    "Hyperion Tank Game", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
    640, 480 + 20 + 20, SDL_WINDOW_SHOWN);
  if (win == nullptr) {
    puts("SDL failed");
    SDL_Quit();
    return 4;
  }

  SDL_Renderer *ren = SDL_CreateRenderer(win, -1, SDL_RENDERER_ACCELERATED);
  if (ren == nullptr){
    puts("SDL failed");
    SDL_DestroyWindow(win);
    SDL_Quit();
    return 1;
  }

  framebuffer = SDL_GetWindowSurface(win);
  gMapSurface = SDL_CreateRGBSurfaceWithFormat(
      0, framebuffer->w, framebuffer->h,
      framebuffer->format->BitsPerPixel,
      framebuffer->format->format);

  gRedrawTargetingDataBar = false;

  SDL_Thread *th = SDL_CreateThread(NetThreadFunc, "net thread", nullptr);

  SDL_Event e;
  while (SDL_AtomicGet(&the_end) == 0) {
    while (SDL_PollEvent(&e)) {
      if (e.type == SDL_QUIT) {
        SDL_AtomicSet(&the_end, 1);
        break;
      }

      if (e.type == SDL_KEYDOWN) {
        if (e.key.keysym.sym == SDLK_UP) {
          gPower += 1;
          if (gPower > 99) {
            gPower = 99;
          }
        }

        if (e.key.keysym.sym == SDLK_DOWN) {
          gPower -= 1;
          if (gPower < 10) {
            gPower = 10;
          }
        }

        if (e.key.keysym.sym == SDLK_RIGHT) {
          gAngle -= 1;
          if (gAngle < 0) {
            gAngle = 0;
          }
        }

        if (e.key.keysym.sym == SDLK_LEFT) {
          gAngle += 1;
          if (gAngle > 180) {
            gAngle = 180;
          }
        }

        if (e.key.keysym.sym == SDLK_1) { gWeapon = 1; }
        if (e.key.keysym.sym == SDLK_2) { gWeapon = 2; }
        if (e.key.keysym.sym == SDLK_3) { gWeapon = 3; }

        if (e.key.keysym.sym == SDLK_SPACE ||
            e.key.keysym.sym == SDLK_KP_SPACE ||
            e.key.keysym.sym == SDLK_RETURN ||
            e.key.keysym.sym == SDLK_RETURN2) {
          if (gReadyToFire && gClient != nullptr) {  // Race condition on disconnect. Meh.
            gReadyToFire = false;
            puts("FIRE!");

            TargetingData t{gWeapon, (float)gPower, (float)gAngle};

            SendTargetingData(gClient, &t);
          }
        }

        if (gClient != nullptr) {
          gRedrawTargetingDataBar = true;
        }
      }
    }

    // Update timer.
    double now = (double)SDL_GetTicks() / 1000.0;
    gDiff = now - gNow;
    gNow = now;

    HandleRendering();

    SDL_UpdateWindowSurface(win);
  }

  SDL_AtomicSet(&the_end, 1);
  SDL_WaitThread(th, nullptr);

  framebuffer = nullptr;
  SDL_FreeSurface(gMapSurface);
  SDL_DestroyRenderer(ren);
  SDL_DestroyWindow(win);
  SDL_Quit();
  return 0;
}
