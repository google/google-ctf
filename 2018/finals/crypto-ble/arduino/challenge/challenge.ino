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

#include <tommath.h>
#include <tomcrypt.h>


//#define PROD
//#define DEBUG

#ifdef DEBUG
#define dbgprintf(...) printf(__VA_ARGS__)
#else
#define dbgprintf(...)
#endif

#ifdef PROD
#define PSS ("acc6bbca472433494")
#define CTF_FLAG ("CTF{fLaGinTh34Ir}")
#else
#define PSS ("thesecret")
#define CTF_FLAG ("CTF{flag}")
#endif


int count = 0;
int d = 2000;
bool is_server = false;

void setup() {
  Serial.begin(115200);

  pinMode(LED_BUILTIN, OUTPUT);
  pinMode(KEY_BUILTIN, INPUT);

  crypt_mp_init("l");
  register_hash(&sha256_desc);
  register_cipher(&aes_desc);
  init_prng();

  digitalWrite(LED_BUILTIN, HIGH);
  delay(2000);
  digitalWrite(LED_BUILTIN, LOW);

  if (digitalRead(KEY_BUILTIN) == 1) {
    Serial.println("Starting as client");
    client_setup();
  } else {
    Serial.println("Starting as server");
    d = 500;
    is_server = true;
    server_setup();
  }

}

void loop() {
  delay(d);

  if (count++ % 2)
    digitalWrite(LED_BUILTIN, HIGH);
  else
    digitalWrite(LED_BUILTIN, LOW);

  if (!is_server) {
    client_loop();
  }

}
