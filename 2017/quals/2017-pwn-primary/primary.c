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
  Primary
  This takes 64 bit integers and filters out the non-primes.
 */

#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <inttypes.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_NUM_THREADS 256
#define MAX_PRIMES_PER_THREAD 4096
#define MAX_NUM_PRIMES  (MAX_NUM_THREADS * MAX_PRIMES_PER_THREAD)
#define PRIMALITY_LOOPS 10
#define RANDOM_STATE_SIZE 128
#define MAX_NUMBER_LIST_SIZE 512
#define MIN(a,b)   ((a) < (b) ? (a) : (b))
#define LOCK(m)    pthread_mutex_lock(&m)
#define UNLOCK(m)  pthread_mutex_unlock(&m)

typedef unsigned __int128 uint128_t;
typedef struct {
  size_t count;
  uint64_t* numbers;
} number_list;

typedef struct {
  number_list input;
  number_list* primes;
  pthread_mutex_t prime_mutex;
  struct random_data* r_data;
} worker_args;

pthread_t threads[MAX_NUM_THREADS];
worker_args args[MAX_NUM_THREADS];
pthread_mutex_t prime_mutex = PTHREAD_MUTEX_INITIALIZER;
struct random_data r_data[256];
char random_states[RANDOM_STATE_SIZE][256];
number_list input;
number_list primes;
char file_buffer[4096];

uint64_t modular_multiplication(uint128_t x, uint128_t y, uint128_t n) {
  return (x * y) % n;
}

uint64_t modular_exponentiation(uint64_t x, uint64_t e, uint64_t n) {
  uint64_t squares[64];
  squares[0] = x % n;

  uint64_t result = 1;
  if (e % 2 == 1) {
    result = squares[0];
  }

  for (int i = 1; i < 64; i++) {
    squares[i] = modular_multiplication(squares[i-1], squares[i-1], n);
    if (e & (1ULL << i)) {
      result = modular_multiplication(result, squares[i], n);
    }
  }
  return result;
}

bool is_probably_prime(uint64_t n, struct random_data* r_data) {
  uint64_t r = 0;
  uint64_t d = n - 1;
  while (d % 2 == 0) {
    d /= 2;
    r++;
  }

  int32_t random_low, random_high;
  random_r(r_data, &random_low);
  random_r(r_data, &random_high);
  uint64_t random = ((uint64_t)(random_high) << 32) | random_low;
  uint64_t x = modular_exponentiation(random % (n-3) + 2, d, n);

  if (x == 1 || x == n - 1)
    return true;

  for (uint64_t i = 0; i < r - 1; i++) {
    x = modular_multiplication(x, x, n);
    if (x == 1)
      return false;
    else if (x == n - 1)
      return true;
  }
  return false;
}

bool is_prime(uint64_t n, struct random_data* r_data) {
  if (n < 2 || n % 2 == 0) {
    return false;
  } else if (n < 4) {
    return true;
  }

  for (int i = 0; i < PRIMALITY_LOOPS; i++) {
    if (!is_probably_prime(n, r_data))
      return false;
  }

  return true;
}

void print_help() {
  FILE* help = fopen("help.txt", "r");
  memset(file_buffer, '\0', 4096);
  fread(file_buffer, sizeof(char), 4095, help);
  printf("%s\n", file_buffer);
}

void filter_primality(number_list* input, number_list* primes,
                      struct random_data* r_data) {
  primes->count = 0;
  for (size_t i = 0; i < input->count; i++) {
    if (is_prime(input->numbers[i], r_data)) {
      primes->numbers[primes->count++] = input->numbers[i];
    }
  }
}

void append(const number_list* source, number_list* destination) {
  size_t new_count = destination->count + source->count;

  if (source->count == 0 || new_count < destination->count)
    return;

  uint64_t* old_numbers = destination->numbers;
  destination->numbers = malloc(new_count * sizeof(uint64_t));

  if (destination->numbers == NULL)
    return;

  if (destination->count) {
    memcpy(destination->numbers, old_numbers,
           destination->count * sizeof(uint64_t));
    free(old_numbers);
  }

  memcpy(destination->numbers + destination->count, source->numbers,
         source->count * sizeof(uint64_t));

  destination->count = new_count;
}

void* worker(void* arg) {
  uint64_t prime_buf[MAX_NUMBER_LIST_SIZE];
  memset(prime_buf, '\0', MAX_NUMBER_LIST_SIZE * sizeof(uint64_t));

  number_list primes = {0, prime_buf};
  worker_args* args = (worker_args*) arg;

  for (size_t i = 0; i < args->input.count; i += MAX_NUMBER_LIST_SIZE) {
    number_list input = {MIN(MAX_NUMBER_LIST_SIZE, args->input.count - i),
                         args->input.numbers + i};
    filter_primality(&input, &primes, args->r_data);

    LOCK(args->prime_mutex);
    append(&primes, args->primes);
    UNLOCK(args->prime_mutex);
  }

  return NULL;
}

int main(int argc, char** argv) {
  bool silent = false;
  if (argc > 2) {
    print_help();
    return 1;
  } else if (argc == 2 && strncmp("--silent", argv[1], 8) == 0){
    silent = true;
  }

  primes.numbers = NULL;
  primes.count = 0;

  input.numbers = malloc(MAX_NUM_PRIMES * sizeof(uint64_t));
  input.count = 0;

  if (!input.numbers) {
    perror("malloc failed");
    return 1;
  }

  int additional = 0;
  while ((additional = fread(input.numbers + input.count, sizeof(uint64_t),
                             MAX_NUM_PRIMES - input.count, stdin))) {
    input.count += additional;
  }

  FILE* help = fopen("flag.txt.doc.exe", "r");
  if (!help) {
    perror("Seed file not found.");
    return 1;
  } else if (fread(file_buffer, sizeof(char), 4096, help) != 4096) {
    perror("Seed file not read.");
    return 1;
  }

  size_t num_threads =
      (input.count + MAX_PRIMES_PER_THREAD - 1) / MAX_PRIMES_PER_THREAD;

  for (size_t i = 0; i < num_threads; i++) {
    args[i].input.count = MIN(MAX_PRIMES_PER_THREAD, input.count);
    input.count -= args[i].input.count;
    args[i].input.numbers = &input.numbers[i * MAX_PRIMES_PER_THREAD];
    args[i].primes = &primes;
    args[i].prime_mutex = prime_mutex;
    initstate_r(0, random_states[i], RANDOM_STATE_SIZE, &r_data[i]);
    srandom_r(file_buffer[i], &r_data[i]);
    args[i].r_data = &r_data[i];
    if (pthread_create(&threads[i], NULL, worker, &args[i]) != 0) {
      perror("pthread_create failed: kablam");
      return 1;
    }
  }

  for (size_t i = 0; i < num_threads; i++) {
    pthread_join(threads[i], NULL);
  }

  if (!silent && primes.count) {
    for (size_t i = 0; i < primes.count; i++) {
      printf("%zu ", primes.numbers[primes.count - 1]);
    }
    printf("\n");
  }
  free(input.numbers);
  free(primes.numbers);
  return 0;
}
