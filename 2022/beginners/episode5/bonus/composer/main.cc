// Copyright 2022 Google LLC
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

// Apologies the poor structure of this code, but given that it's an ad-hoc
// CTF-like challenge I decided for once to not over-engineer something.
// -- gynvael
//
// Do this:
// # echo 16777216 > /proc/sys/fs/pipe-max-size
// # cat /proc/sys/fs/pipe-max-size
// 16777216
// (otherwise performance is terrible)

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <thread>
#include <tuple>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <NetSock.h>
#include "config.h"

#define _TOSTR(x) #x
#define TOSTR(x) _TOSTR(x)

#define COUNTOF(x) (sizeof(x)/sizeof(*x))

struct RGB {
  uint8_t r;
  uint8_t g;
  uint8_t b;
};

struct RGBA {
  uint8_t r;
  uint8_t g;
  uint8_t b;
  uint8_t a;
};

struct Image {
  uint32_t w;
  uint32_t h;
  std::vector<RGB> px;

  void reset(uint32_t w, uint32_t h, RGB color);
  void load_from_rgb(uint32_t w, uint32_t h, const char *fname);
  void dump_to_rgb(const char *fname);
};

struct ImageAlpha {
  uint32_t w;
  uint32_t h;
  std::vector<RGBA> px;

  void load_from_rgba(uint32_t w, uint32_t h, const char *fname);
};

struct TextBuffer {
  uint32_t w;  // In characters.
  uint32_t h;
  std::vector<uint8_t> text;

  RGB fg{0x68, 0xff, 0xbb};
  RGB bg{0, 0, 0};

  void reset(uint32_t w, uint32_t h);
  void render(Image *dst);
};

// IPC protocol (via UDP):
//   Offset  Type/Size  Description
//   0       uint8_t    opcode id
//   1-...   N*uint8_t  payload (interpretation depends on opcode id)
// Opcode id 0 means "text buffer content" and is handled internally.
// Any other opcode id is considered a custom opcode and is passed to the user.
class IngressHandler {
 public:
  IngressHandler(uint16_t port, TextBuffer *text, Image *img) :
       port_(port), text_(text), img_(img) {
    packet_.resize(0x10000);
  }

  // Returns -1 on error, positive integer on custom opcode (data is filled with
  // received custom opcode payload in such case).
  // It doesn't return for opcode id 0x00 (handles it internally).
  std::tuple<int, const uint8_t*, size_t> handle();

 private:
  uint16_t port_;
  TextBuffer *text_;
  Image *img_;
  NetSock s_;
  std::vector<uint8_t> packet_;
};

const constexpr int64_t FPS = 30;
const constexpr int64_t USEC_PER_FRAME = 1000000 / FPS;

const constexpr uint32_t W = 1920;
const constexpr uint32_t H = 1080;
const constexpr uint32_t BPP = 3;  // That's BYTES per pixel.
const char *BG_IMG = "background.rgb";
Image bg_img;

const constexpr uint32_t BASIC_UDP_PORT = 23400;
const constexpr uint32_t BASIC_X = 64;
const constexpr uint32_t BASIC_Y = 76;
const constexpr uint32_t BASIC_W = 576;
const constexpr uint32_t BASIC_H = 448;
const constexpr uint32_t BASIC_TEXT_W = 36;
const constexpr uint32_t BASIC_TEXT_H = 14;

const constexpr uint32_t VOTE_UDP_PORT = 23401;
const constexpr uint32_t VOTE_X = 64;
const constexpr uint32_t VOTE_Y = 556;
const constexpr uint32_t VOTE_W = 576;
const constexpr uint32_t VOTE_H = 448;
const constexpr uint32_t VOTE_TEXT_W = 36;
const constexpr uint32_t VOTE_TEXT_H = 14;

const constexpr uint32_t CAM_X = 712;
const constexpr uint32_t CAM_Y = 227;
const constexpr uint32_t CAM_W = 1119;
const constexpr uint32_t CAM_H = 628;
const char *CAM_FRAME_NAMES[] = {
  "lamp_on.rgb",
  "lamp_off.rgb",
  "lamp_turning_on_0.rgb",
  "lamp_turning_on_1.rgb",
  "lamp_turning_on_2.rgb",
  "lamp_turning_on_3.rgb",
  "lamp_turning_off_0.rgb",
  "lamp_turning_off_1.rgb",
  "lamp_turning_off_2.rgb",
  "lamp_turning_off_3.rgb"
};
const int CAM_FRAME_ON[]          = { 0 };
const int CAM_FRAME_OFF[]         = { 1 };
const int CAM_FRAME_TURNING_ON[]  = { 2, 3, 4, 5 };
const int CAM_FRAME_TURNING_OFF[] = { 6, 7, 8, 9 };
const int *CAM_ANIMS[] = {
  CAM_FRAME_ON,
  CAM_FRAME_OFF,
  CAM_FRAME_TURNING_ON,
  CAM_FRAME_TURNING_OFF
};
const int CAM_ANIMS_LENGTH[] = {
  COUNTOF(CAM_FRAME_ON),
  COUNTOF(CAM_FRAME_OFF),
  COUNTOF(CAM_FRAME_TURNING_ON),
  COUNTOF(CAM_FRAME_TURNING_OFF)
};
std::vector<Image> cam_frames;

const constexpr uint32_t FONT_W = 144;
const constexpr uint32_t FONT_H = 136;
const constexpr uint32_t FONT_CHAR_W = 8;
const constexpr uint32_t FONT_CHAR_PAD_W = 1;
const constexpr uint32_t FONT_CHAR_H = 16;
const constexpr uint32_t FONT_CHAR_PAD_H = 1;
const char *FONT_IMG = "display-8x16.rgb";
Image font_img;

const constexpr uint32_t GLASS_W = 576;
const constexpr uint32_t GLASS_H = 448;
const char *GLASS_IMG = "glass.rgba";
ImageAlpha glass_img;

// Actual frame buffers for each element.
// Note: I'm not doing double-buffering on purpose, since I kinda want the
// tearing effect.
Image frame;
Image basic;
Image vote;
Image cam;

TextBuffer basic_text;
TextBuffer vote_text;

std::atomic_int cam_state;  // 0 - showing light off, 1 - showing light on.

template<typename T, uint32_t V>
static void __load_from_raw(T *img, uint32_t w, uint32_t h, const char *fname) {
  const size_t sz_px = (size_t)w * (size_t)h;
  const size_t sz_bytes = sz_px * V;
  img->px.resize(sz_px);

  FILE *f = fopen(fname, "rb");
  if (f == nullptr) {
    fprintf(stderr, "fatal: could not load image '%s'\n", fname);
    exit(1);
  }

  size_t read = fread(img->px.data(), 1, sz_bytes, f);
  if (read != sz_bytes) {
    fprintf(stderr, "fatal: expected more bytes from '%s'\n", fname);
    exit(1);
  }

  fclose(f);

  img->w = w;
  img->h = h;
  printf("Loaded '%s'\n", fname);
}

void Image::load_from_rgb(uint32_t w, uint32_t h, const char *fname) {
  __load_from_raw<Image, 3>(this, w, h, fname);
}

void ImageAlpha::load_from_rgba(uint32_t w, uint32_t h, const char *fname) {
  __load_from_raw<ImageAlpha, 4>(this, w, h, fname);
}

void Image::reset(uint32_t w, uint32_t h, RGB color) {
  const size_t sz_px = (size_t)w * (size_t)h;
  px.resize(sz_px);
  std::fill(px.begin(), px.end(), color);

  this->w = w;
  this->h = h;
}

void Image::dump_to_rgb(const char *fname) {
  FILE *f = fopen(fname, "wb");
  if (f == nullptr) {
    fprintf(stderr, "error: could not dump image to '%s'\n", fname);
    return;
  }

  fwrite(px.data(), 1, w * h * BPP, f);

  fclose(f);
}

void TextBuffer::reset(uint32_t w, uint32_t h) {
  const size_t sz = w * h;
  text.resize(sz);
  std::fill(text.begin(), text.end(), ' ');

  this->w = w;
  this->h = h;
}

void TextBuffer::render(Image *dst) {
  const uint32_t expected_img_w = w * FONT_CHAR_W * 2;
  const uint32_t expected_img_h = h * FONT_CHAR_H * 2;
  if (dst->w != expected_img_w || dst->h != expected_img_h) {
    fprintf(stderr,
            "fatal: wrong destination image size for text buffer"
            "(w: %u vs %u, h: %u vs %u)\n",
            dst->w, expected_img_w, dst->h, expected_img_h
    );
    exit(1);
  }

  RGB *dstpx = dst->px.data();
  for (uint32_t j = 0; j < dst->h; j++) {
    for (uint32_t i = 0; i < dst->w; i++, dstpx++) {
      const uint32_t text_x = i / (FONT_CHAR_W * 2);
      const uint32_t text_y = j / (FONT_CHAR_H * 2);
      const uint32_t text_idx = text_x + text_y * w;
      const uint8_t ch = text[text_idx] & 0x7f;
      const bool attr = bool(text[text_idx] & 0x80);

      if (ch == 0x00 || ch == 0x20 || ch >= 0x80) {
        *dstpx = attr ? fg : bg;
        continue;
      }

      const uint32_t font_x =
          (ch & 0xf) * (FONT_CHAR_W + FONT_CHAR_PAD_W) +
          (i % (FONT_CHAR_W * 2)) / 2;

      const uint32_t font_y =
          (ch / 0x10) * (FONT_CHAR_H + FONT_CHAR_PAD_H) +
          (j % (FONT_CHAR_H * 2)) / 2;

      const uint32_t font_idx =
          font_x + font_y * FONT_W;

      if (font_img.px[font_idx].r) {
        *dstpx = attr ? bg : fg;
      } else {
        *dstpx = attr ? fg : bg;
      }
    }
  }
}

void img_copy(Image *dst, uint32_t x, uint32_t y, const Image *src) {
  // Note: I don't do any boundary checks. YOLO.
  const uint32_t line_sz_bytes = BPP * src->w;
  for (uint32_t j = 0; j < src->h; j++) {
    const RGB *src_line = &src->px[j * src->w];
    RGB *dst_line = &dst->px[(y + j) * dst->w + x];
    memcpy(dst_line, src_line, line_sz_bytes);
  }
}

void img_copy_noisy(
    Image *dst, uint32_t x, uint32_t y, const Image *src) {
  // Using xorshift64 for noise.
  uint64_t xs = (uint64_t)rand() | ((uint64_t)rand() << 31);

  // Note: I don't do any boundary checks. YOLO.
  for (uint32_t j = 0; j < src->h; j++) {
    const RGB *src_line = &src->px[j * src->w];
    RGB *dst_line = &dst->px[(y + j) * dst->w + x];
    for (uint32_t i = 0; i < src->w; i++) {
      const RGB &srcpx = src_line[i];
      RGB &dstpx = dst_line[i];

      dstpx.r = srcpx.r ^ ((xs >> 0) & 0x3);
      dstpx.g = srcpx.g ^ ((xs >> 8) & 0x3);
      dstpx.b = srcpx.b ^ ((xs >> 16) & 0x3);

      xs ^= xs << 13; xs ^= xs >> 7; xs ^= xs << 17;
    }
  }
}

void img_copy_alpha_special(
    Image *dst, uint32_t x, uint32_t y, const ImageAlpha *src) {
  // Note: I don't do any boundary checks. YOLO.
  for (uint32_t j = 0; j < src->h; j++) {
    const RGBA *src_line = &src->px[j * src->w];
    RGB *dst_line = &dst->px[(y + j) * dst->w + x];
    for (uint32_t i = 0; i < src->w; i++) {
      const RGBA &srcpx = src_line[i];
      RGB &dstpx = dst_line[i];
      if (srcpx.a == 0) {
        continue;
      }

      uint32_t a = srcpx.a;
      uint32_t na = 255 - a;

      dstpx.r = (uint32_t(dstpx.r) * na + uint32_t(srcpx.r) * a) / 256;
      dstpx.g = (uint32_t(dstpx.g) * na + uint32_t(srcpx.g) * a) / 256;
      dstpx.b = (uint32_t(dstpx.b) * na + uint32_t(srcpx.b) * a) / 256;
    }
  }
}

void compose_frame() {
  // Run every ~33.3ms.
  // Note: It takes around 3ms to render the frame at the moment.
  clock_t start = clock();
  img_copy(&frame, BASIC_X, BASIC_Y, &basic);
  img_copy(&frame, VOTE_X, VOTE_Y, &vote);
  img_copy(&frame, CAM_X, CAM_Y, &cam);
  img_copy_alpha_special(&frame, BASIC_X, BASIC_Y, &glass_img);
  img_copy_alpha_special(&frame, VOTE_X, VOTE_Y, &glass_img);
  clock_t end = clock();

  //printf("tm: %f\n", (double)(end - start) / (double)CLOCKS_PER_SEC);
}

static inline int64_t diff_microseconds(timeval *a, timeval *b) {
  int64_t sec = a->tv_sec - b->tv_sec;
  int32_t usec = (int32_t)a->tv_usec - (int32_t)b->tv_usec;
  return usec + sec * 1000000LL;
}

static inline void add_microseconds(timeval *tv, int64_t usec) {
  // Note: This works only for positive values of usec which aren't too big.
  tv->tv_usec += usec;
  if (tv->tv_usec > 1000000) {
    tv->tv_sec += tv->tv_usec / 1000000;
    tv->tv_usec %= 1000000;
  }
}

void thread_ffmpeg() {
  // Handles making sure ffmpeg is running and is receiving frames every 33 or
  // so ms.

  signal(SIGPIPE, SIG_IGN);

  for (;;) {
    usleep(1 * 1000 * 1000);
    puts("Re-starting ffmpeg...");

    int pipefd[2]{-1, -1};
    if (pipe(pipefd) == -1) {
      perror("thread_ffmpeg");
      continue;
    }

    int pipe_buf_sz = ((W * H * BPP) + 4095) & 0xfffff000;
    int pipe_sz = fcntl(pipefd[1], F_SETPIPE_SZ, pipe_buf_sz);
    if (pipe_sz < pipe_buf_sz) {
      perror("thread_ffmpeg");
      fprintf(stderr, "warning: failed to set pipe buffer to frame size (%i)\n",
              pipe_sz);
    }

    pid_t p = fork();
    if (p == -1) {
      close(pipefd[0]);
      close(pipefd[1]);
      perror("thread_ffmpeg");
      continue;
    }

    if (p == 0) {
      // Child.
      close(pipefd[1]);   // Close write-end.
      close(0);           // Close original stdin.
      dup2(pipefd[0], 0); // Use pipe's read-end as stdin.
      close(pipefd[0]);   // Close the redundant descriptor.

      const char *ffmpeg_argv[] = {
        "ffmpeg",
        "-y",              // Overwrite destination.
        "-thread_queue_size", "4096",

        // Input params.
        "-re",
        "-f", "rawvideo",
        "-pix_fmt", "rgb24",
        "-s", "1920x1080",
        "-r", "30",
        "-i", "-",         // Get input from stdin.

        // Input fake audio.
        "-f", "lavfi",
        "-i", "anullsrc",

        // Output params.
        "-pix_fmt", "yuv420p",
        "-c:v", "libx264",
        //"-profile:v", "main",
        "-preset", "superfast",
        "-crf", "23",
        "-r", "30",
        "-g", "60",
        "-b:v", "4500k",
        "-c:a", "libmp3lame",
        "-ar", "44100",
        "-threads", "2",
        //"-qscale", "3",
        "-b:a", "128k",
        "-bufsize", "960k",
        "-f", "flv",
        "rtmp://a.rtmp.youtube.com/live2/" YOUTUBE_KEY,
        nullptr
      };

      execvp(ffmpeg_argv[0], (char *const*)ffmpeg_argv);
      perror("thread_ffmpeg");
      _exit(0);
    }

    // Parent.
    close(pipefd[0]);  // Close read-end.
    fprintf(stderr, "note: ffmpeg started at pid %i\n", p);

    timeval tv_prev;
    gettimeofday(&tv_prev, nullptr);
    uint8_t leap_counter = 0;
    int64_t delay_usec = USEC_PER_FRAME;
    for (;;) {
      clock_t start = clock();

      timeval tv_now;
      gettimeofday(&tv_now, nullptr);

      int64_t usec = diff_microseconds(&tv_now, &tv_prev);
      if (usec < delay_usec) {
        usleep(5000);  // 5ms.
        continue;
      }

      int32_t frame_lag = usec / delay_usec;
      if (frame_lag > 2) {
        fprintf(stderr, "warning: frame lag is %i frames\n", frame_lag);
      }

      add_microseconds(&tv_prev, delay_usec);

      // Fix time drift (would be noticeable after a few days if my math is
      // correct).
      // TODO: Re-check math here (leap_counter 3 or 30?).
      leap_counter++;
      if (leap_counter == 3) {
        leap_counter = 0;
        delay_usec = USEC_PER_FRAME + 1;
      } else {
        delay_usec = USEC_PER_FRAME;
      }

      // Send frame.
      compose_frame();
      size_t sz = W * H * BPP;
      ssize_t ret = write(pipefd[1], frame.px.data(), sz);
      if (ret == -1) {
        perror("thread_ffmpeg");
        break;
      }

      if ((size_t)ret != sz) {
        fprintf(stderr,
                "error: couldn't send a whole frame to ffmpeg (restarting)\n");
        break;
      }

      clock_t end = clock();

      //printf("tm: %f\n", (double)(end - start) / (double)CLOCKS_PER_SEC);
    }

    fprintf(stderr, "note: ffmpeg failed or something\n");

    close(pipefd[1]);  // Close write-end as well.

    if (kill(p, SIGKILL) == -1) {
      perror("thread_ffmpeg");
    }

    int wstatus;
    if (waitpid(p, &wstatus, 0) == -1) {
      perror("thread_ffmpeg");
    }
  }
}

std::tuple<int, const uint8_t*, size_t>
IngressHandler::handle() {
  if (s_.GetDescriptor() == -1) {
    if (!s_.ListenUDP(port_, "127.0.0.1")) {
      fprintf(stderr, "fatal: couldn't bind to UDP port %u\n", port_);
      _exit(1);
    }
    fprintf(stderr, "note: listening on UDP port %u\n", port_);
  }

  for (;;) {
    int ret = s_.ReadUDP(packet_.data(), packet_.size(), nullptr, nullptr);
    if (ret < 0) {
      fprintf(stderr, "warning: failed to receive some UDP packet\n");
      continue;
    }

    if (ret == 0) {
      fprintf(stderr, "note: funny, got a 0-sized UDP packet\n");
      continue;
    }

    uint8_t opcode = packet_[0];
    const int payload_sz = ret - 1;

    if (opcode == 0) {
      // TextBuffer content.
      const int expected_sz = (int)(text_->w * text_->h);
      if (payload_sz != expected_sz) {
        fprintf(stderr, "warning: received text buffer too small (%i vs %i)\n",
                payload_sz, expected_sz);
      }

      int sz = std::min(expected_sz, payload_sz);
      memcpy(text_->text.data(), &packet_[1], sz);
      text_->render(img_);
      continue;
    }

    return { (int)opcode, &packet_[1], payload_sz };
  }

  return { -1, nullptr, 0 };
}

void thread_vote() {
  IngressHandler ingress(VOTE_UDP_PORT, &vote_text, &vote);

  for (;;) {
    auto [ opcode, payload, payload_sz ] = ingress.handle();
    if (opcode < 0) {
      break;
    }

    fprintf(
        stderr,
        "warning: vote received unknown opcode %i with %lu bytes of payload\n",
        opcode, payload_sz
    );
  }
}

void thread_basic() {
  IngressHandler ingress(BASIC_UDP_PORT, &basic_text, &basic);

  for (;;) {
    auto [ opcode, payload, payload_sz ] = ingress.handle();
    if (opcode < 0) {
      break;
    }

    if (opcode == 1) {
      if (payload_sz != 1) {
        fprintf(stderr, "warning: cam control packet has invalid size (%lu)\n",
                payload_sz);
      }

      if (payload_sz > 0) {
        cam_state.store((int)payload[0]);
      }

      continue;
    }

    fprintf(
        stderr,
        "warning: BASIC received unknown opcode %i with %lu bytes of payload\n",
        opcode, payload_sz
    );
  }
}

void thread_cam() {
  enum {
    STATE_ON,
    STATE_OFF,
    STATE_TURNING_ON,
    STATE_TURNING_OFF
  } state = STATE_OFF;

  int frame_no = 0;

  for (;;) {
    // This will give a bit less than 30 FPS, but that's fine.
    usleep(33334);

    const int light_on = cam_state.load();

    switch (state) {
      case STATE_ON:
        if (!light_on) {
          state = STATE_TURNING_OFF;
          frame_no = 0;
        } else {
          frame_no++;
        }
        break;

      case STATE_OFF:
        if (!light_on) {
          frame_no++;
        } else {
          state = STATE_TURNING_ON;
          frame_no = 0;
        }
        break;

      case STATE_TURNING_ON:
        if (!light_on) {
          state = STATE_TURNING_OFF;
          frame_no = 0;  // TODO: perhaps some better logic.
        } else {
          frame_no++;
          if (frame_no == CAM_ANIMS_LENGTH[state]) {
            state = STATE_ON;
            frame_no = 0;
          }
        }
        break;

      case STATE_TURNING_OFF:
        if (!light_on) {
          frame_no++;
          if (frame_no == CAM_ANIMS_LENGTH[state]) {
            state = STATE_OFF;
            frame_no = 0;
          }
        } else {
          state = STATE_TURNING_ON;
          frame_no = 0;  // TODO: perhaps some better logic.
        }
        break;
    }

    if (frame_no >= CAM_ANIMS_LENGTH[state]) {
      frame_no = 0;
    }

    img_copy_noisy(&cam, 0, 0, &cam_frames[CAM_ANIMS[state][frame_no]]);
  }
}

void load_cam_frames() {
  const constexpr size_t frame_count = COUNTOF(CAM_FRAME_NAMES);
  cam_frames.resize(frame_count);
  for (size_t i = 0; i < frame_count; i++) {
    cam_frames[i].load_from_rgb(CAM_W, CAM_H, CAM_FRAME_NAMES[i]);
  }
}

int main() {
  NetSock::InitNetworking();

  // Load resources and initialize various buffers.
  bg_img.load_from_rgb(W, H, BG_IMG);
  font_img.load_from_rgb(FONT_W, FONT_H, FONT_IMG);
  glass_img.load_from_rgba(GLASS_W, GLASS_H, GLASS_IMG);

  frame.reset(W, H, RGB{255, 76, 123});
  img_copy(&frame, 0, 0, &bg_img);

  basic.reset(BASIC_W, BASIC_H, RGB{0, 76, 0});
  basic_text.reset(BASIC_TEXT_W, BASIC_TEXT_H);

  vote.reset(VOTE_W, VOTE_H, RGB{0, 0, 76});
  vote_text.reset(VOTE_TEXT_W, VOTE_TEXT_H);

  cam.reset(CAM_W, CAM_H, RGB{200, 200, 200});
  load_cam_frames();

  //frame.dump_to_rgb("frame.raw");

  // Start handler threads.
  std::thread ffmpeg_th(thread_ffmpeg);
  std::thread vote_th(thread_vote);
  std::thread basic_th(thread_basic);
  std::thread cam_th(thread_cam);

  puts("All threads have been starting, going to sleep.");
  ffmpeg_th.join();  // Note: I don't really think any of these threads will
  vote_th.join();    // return.
  basic_th.join();
  cam_th.join();

  puts("Bye!");
}
