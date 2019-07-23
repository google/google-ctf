/* Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <complex.h>
#include <errno.h>
#include <math.h>
#include <pulse/error.h>
#include <pulse/simple.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define LOG_PERIOD_SAMPLES 13
#define PERIOD_SAMPLES (1 << LOG_PERIOD_SAMPLES)
#define PI 3.1415926535897932384626433832795L
#define THRESHOLD 1.0
#define MAX_COUNT_SINCE_KEY 20

#define DTMF_0 13
#define DTMF_1 0
#define DTMF_2 1
#define DTMF_3 2
#define DTMF_4 4
#define DTMF_5 5
#define DTMF_6 6
#define DTMF_7 8
#define DTMF_8 9
#define DTMF_9 10
#define DTMF_A 3
#define DTMF_B 7
#define DTMF_C 11
#define DTMF_D 15
#define DTMF_STAR 12
#define DTMF_HASH 14

#define KEY0 DTMF_8
#define KEY1 DTMF_5
#define KEY2 DTMF_9
#define KEY3 DTMF_6
#define KEY4 DTMF_8
#define KEY5 DTMF_7
#define KEY6 DTMF_2
#define KEY7 DTMF_0
#define KEY8 DTMF_1

int reverse_bits(int i) {
  int result = 0;
  for (int j = 0; j < LOG_PERIOD_SAMPLES; ++j) {
    int jbit = (i & (1 << j)) >> j;
    result |= jbit << (LOG_PERIOD_SAMPLES - 1 - j);
  }
  return result;
}

void bit_flip(float* a, double complex* b) {
  for (int i = 0; i < PERIOD_SAMPLES; ++i) {
    b[reverse_bits(i)] = a[i];
  }
}

// the compiler generates a lot of boilerplate for complex arithmetic,
// that shouldn't really be part of the challenge to decipher.
double complex complex_mul(double complex a, double complex b) { return a * b; }
double complex complex_add(double complex a, double complex b) { return a + b; }
double complex complex_sub(double complex a, double complex b) { return a - b; }

// inner FFT computation
void y(double complex* samples, int offset, int unity_step) {
  for (int k = 0; k < unity_step / 2; ++k) {
    double complex omega_k = cexp(-2.0 * PI * I * k / unity_step);
    int u_i = offset + k;
    int t_i = offset + k + unity_step / 2;

    double complex u = samples[u_i];
    double complex t = complex_mul(omega_k, samples[t_i]);

    samples[u_i] = complex_add(u, t);
    samples[t_i] = complex_sub(u, t);
  }
}

// FFT
void x(float* buf, double complex* samples) {
  bit_flip(buf, samples);
  for (int p = 1; p <= LOG_PERIOD_SAMPLES; ++p) {
    const int unity_step = 1 << p;

    for (int o = 0; o < PERIOD_SAMPLES; o += unity_step) {
      y(samples, o, unity_step);
    }
  }
}

double f(double complex* samples, int freq) {
  return cabs(samples[freq * PERIOD_SAMPLES / 44100]);
}

#ifdef DEBUG
void print_dtmf(double complex* samples) {
  printf(
      "%.1f(1209Hz) %.1f(1336Hz) %.1f(1477Hz) %.1f(1633Hz) %.1f(697Hz) "
      "%.1f(770Hz) %.1f(852Hz) %.1f(941Hz)\n",
      f(samples, 1209), f(samples, 1336), f(samples, 1477), f(samples, 1633),
      f(samples, 697), f(samples, 770), f(samples, 852), f(samples, 941));
}
#endif

typedef struct {
  int count_since_key;
  int stage;
  bool need_reset;
} state_t;

// state update
int r(state_t* state, double complex* samples) {
#ifdef DEBUG
  printf("count = %d, stage = %d, need_reset = %d\n", state->count_since_key,
         state->stage, state->need_reset);
#endif
  state->count_since_key++;
  if (state->count_since_key > MAX_COUNT_SINCE_KEY) {
    // fail condition
    return -1;
  }

  double tones1[] = {f(samples, 1209), f(samples, 1336), f(samples, 1477),
                     f(samples, 1633)};
  int tone1 = -1;
  double tone1_max = THRESHOLD;
  for (int i = 0; i < 4; ++i) {
    if (tones1[i] > tone1_max) {
      tone1 = i;
      tone1_max = tones1[i];
    }
  }

  double tones2[] = {f(samples, 697), f(samples, 770), f(samples, 852),
                     f(samples, 941)};
  int tone2 = -1;
  double tone2_max = THRESHOLD;
  for (int i = 0; i < 4; ++i) {
    if (tones2[i] > tone2_max) {
      tone2 = i;
      tone2_max = tones2[i];
    }
  }
#ifdef DEBUG
  printf("tone1 = %d, tone2 = %d\n", tone1, tone2);
#endif

  if (state->need_reset) {
    if (tone1 < 0 && tone2 < 0) {
#ifdef DEBUG
      printf("stage reset\n");
#endif
      state->need_reset = false;
      state->count_since_key = 0;
    }
    // otherwise just wait
  } else if (tone1 >= 0 && tone2 >= 0) {
    int decode = tone1 | (tone2 << 2);
#ifdef DEBUG
    printf("decoded tone %d\n", decode);
#endif
    bool success = false;
    switch (state->stage) {
      case 0:
        success = decode == KEY0;
        break;
      case 1:
        success = decode == KEY1;
        break;
      case 2:
        success = decode == KEY2;
        break;
      case 3:
        success = decode == KEY3;
        break;
      case 4:
        success = decode == KEY4;
        break;
      case 5:
        success = decode == KEY5;
        break;
      case 6:
        success = decode == KEY6;
        break;
      case 7:
        success = decode == KEY7;
        break;
      case 8:
        if (decode == KEY8) {
          // success condition
          return 0;
        }
        break;
    }
    if (!success) {
      // fail condition
      return -1;
    }
    state->stage++;
    state->count_since_key = 0;
    state->need_reset = true;
#ifdef DEBUG
    printf("stage success, new stage = %d\n", state->stage);
#endif
  }
  // continue condition
  return 1;
}

int main(int argc, char** argv) {
  static const pa_sample_spec ss = {
      .format = PA_SAMPLE_FLOAT32LE, .rate = 44100, .channels = 1};
  int err;
  pa_simple* s = pa_simple_new(NULL, argv[0], PA_STREAM_RECORD, NULL, "record",
                               &ss, NULL, NULL, &err);

  if (s == NULL) {
    fprintf(stderr, "pa_simple_new() failed: %s\n", pa_strerror(err));
    return 1;
  }

  state_t state = {.count_since_key = 0, .stage = 0, .need_reset = false};
  while (true) {
    float buf[PERIOD_SAMPLES];
    double complex samples[PERIOD_SAMPLES];

    if (pa_simple_read(s, buf, sizeof(buf), &err) < 0) {
      fprintf(stderr, "pa_simple_read() failed: %s\n", pa_strerror(err));
      return 1;
    }

    x(buf, samples);

    int ret = r(&state, samples);
    if (ret < 0) {
      fprintf(stderr, "FAILED\n");
      return 1;
    }
    if (ret == 0) {
      fprintf(stderr, "SUCCESS\n");
      break;
    }
  }

  pa_simple_free(s);

  return 0;
}
