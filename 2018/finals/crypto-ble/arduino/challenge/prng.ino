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

int mysprng_start(prng_state *prng);
int mysprng_import(const unsigned char *in, unsigned long inlen, prng_state *prng);
int mysprng_export(unsigned char *out, unsigned long *outlen, prng_state *prng);
int mysprng_add_entropy(const unsigned char *in, unsigned long inlen, prng_state *prng);
unsigned long mysprng_read(unsigned char *out, unsigned long outlen, prng_state *prng);
int mysprng_done(prng_state *prng);
int mysprng_ready(prng_state *prng);


#define UNIT 0xff
static int random32(uint8_t *dest, size_t size) {
  int i = 0;
  for (i = 0; i < size; i++) {
    vTaskDelay(30);
    uint32_t randomNumber = esp_random();
    *(dest + i) = (uint8_t)(randomNumber & UNIT);
  }

#ifdef DEBUG
  printf("random: ");
  print_hex(dest,size);
#endif
  
  return i;
}

unsigned int generate_nonce() {
  unsigned int n;
  random32((uint8_t *)&n, sizeof(n));
  return n;
}

const struct ltc_prng_descriptor mysprng_desc =
{
    "mysprng", 0,
    &mysprng_start,
    &mysprng_add_entropy,
    &mysprng_ready,
    &mysprng_read,
    &mysprng_done,
    &mysprng_export,
    &mysprng_import,
    &mysprng_test
};


int mysprng_start(prng_state *prng)
{
   return CRYPT_OK;
}

int mysprng_add_entropy(const unsigned char *in, unsigned long inlen, prng_state *prng)
{
   return CRYPT_OK;
}


int mysprng_ready(prng_state *prng)
{
   return CRYPT_OK;
}


unsigned long mysprng_read(unsigned char *out, unsigned long outlen, prng_state *prng)
{
   LTC_ARGCHK(out != NULL);
   return random32(out, outlen);
}

int mysprng_done(prng_state *prng)
{
   return CRYPT_OK;
}

int mysprng_export(unsigned char *out, unsigned long *outlen, prng_state *prng)
{
   LTC_ARGCHK(outlen != NULL);

   *outlen = 0;
   return CRYPT_OK;
}


int mysprng_import(const unsigned char *in, unsigned long inlen, prng_state *prng)
{
   return CRYPT_OK;
}


int mysprng_test(void)
{
   return CRYPT_OK;

}

void init_prng() {
  register_prng(&mysprng_desc);
}
