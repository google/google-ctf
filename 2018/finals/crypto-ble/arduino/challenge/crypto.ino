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

#define IV_LEN (12)
#define TAG_LEN (16)

enum ACTION {
  NONE = -1,
  PARAMS,
  NONCE,
  PROOF,
  FLAG,
  ECHO,
  ERR,
  MORE_DATA = 0x80,
  EOT = 0xFF
};


int hmac(const unsigned char *key, unsigned long keylen, const unsigned char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen) {
  return hmac_memory(find_hash("sha256"), key, keylen, in, inlen, out, outlen);
}

int hmac_nonce_pss(const unsigned char *key, unsigned long keylen, unsigned int nonce, const unsigned char *pss, unsigned char *out, unsigned long *outlen) {
  hmac_state st;

  hmac_init(&st, find_hash("sha256"), key, keylen);
  hmac_process(&st, (const unsigned char*)&nonce, sizeof(nonce));
  hmac_process(&st, pss, strlen((char*)pss));
  return hmac_done(&st, out, outlen);
}

void print_hex(const uint8_t * num, size_t len) {
  int i;
  for (i = 0; i < len; i++) {
    printf("%02x", num[i]);
  }
  printf("\n");
}

class CryptoService {
  private:
    bool is_server;
    ecc_key key, other_key;
    unsigned int nonce, other_nonce;
    bool authenticated;
    bool exchanged_keys;
    unsigned char secret[32];
    long unsigned int secret_length;

  public:
    CryptoService(bool _is_server);
    ~CryptoService();

    void setExchanged(bool v);
    bool exchangedKeys();
    void setAuthenticated(bool b);
    bool isAuthenticated();
    void setOtherNonce(unsigned int n);
    unsigned int getNonce() ;
    bool verifyOtherProof(const unsigned char *mac, int length);
    void writeProof(unsigned char *data, unsigned long *outlen);
    int readKey(const unsigned char *data, int length);
    int calcSecret();
    int writePubKey(unsigned char *buff, long unsigned int *olen);
    void writeFlag(unsigned char *buff, long unsigned int *olen);
    int decrypt(unsigned char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen);

};
CryptoService::CryptoService(bool _is_server) {
  is_server = _is_server;
  authenticated = false;
  exchanged_keys = false;
  getNonce();


  ecc_make_key(NULL, find_prng("mysprng"), 32, &key);
  memset(&other_key, 0, sizeof(other_key));

#ifdef DEBUG
  char tmp[1024];
  mp_tohex((mp_int*)key.k, tmp);
  printf("k %s\n", tmp);
  mp_tohex((mp_int*)key.pubkey.x, tmp);
  printf("x %s\n", tmp);
  mp_tohex((mp_int*)key.pubkey.y, tmp);
  printf("y %s\n", tmp);
#endif

}

CryptoService::~CryptoService() {
  ecc_free(&key);
  ecc_free(&other_key);
}


void CryptoService::setExchanged(bool v) {
  exchanged_keys = v;
}

bool CryptoService::exchangedKeys() {
  return exchanged_keys;
}

void CryptoService::setAuthenticated(bool b) {
  authenticated = b;
}

bool CryptoService::isAuthenticated() {
  return exchanged_keys && authenticated;
}

void CryptoService::setOtherNonce(unsigned int n) {
  other_nonce = n;

  dbgprintf("other_nonce %08x\n", other_nonce);
}

unsigned int CryptoService::getNonce() {
  nonce = generate_nonce();

  dbgprintf("my nonce %08x\n", nonce);

  return nonce;
}

bool CryptoService::verifyOtherProof(const unsigned char *mac, int length) {
  setAuthenticated(false);

  if (length != 32) return false;

  unsigned char out[MAXBLOCKSIZE];
  unsigned long outlen = MAXBLOCKSIZE;


  hmac_nonce_pss(secret, secret_length, nonce, (const unsigned char*)PSS, out, &outlen);

#ifdef DEBUG
  printf("recv_hmac ");
  print_hex(mac, length);
  printf("calc_hmac ");
  print_hex(out, outlen);
#endif

  if (outlen != 32)
    return false;

  if (memcmp(mac, out, outlen) == 0) {
    setAuthenticated(true);
    return true;
  }

  return false;
}
void CryptoService::writeProof(unsigned char *data, unsigned long *outlen) {
  data[0] = PROOF;
  (*outlen)--;

  hmac_nonce_pss(secret, secret_length, other_nonce, (const unsigned char*)PSS, data + 1, outlen);
  (*outlen)++;
}
int CryptoService::readKey(const unsigned char *data, int length) {
  dbgprintf("read_key()\n");

  ecc_free(&other_key);

  if (!length) return -1;
  int err = ecc_import_openssl(data, length, &other_key);

#ifdef DEBUG
  if (err != CRYPT_OK) {
    printf("failed read client key\n");
  } else {
    printf("received key\n");
    char tmp[1024];
    mp_tohex((mp_int*)other_key.dp.prime, tmp);
    printf("p %s\n", tmp);
    mp_tohex((mp_int*)other_key.dp.A, tmp);
    printf("a %s\n", tmp);
    mp_tohex((mp_int*)other_key.dp.B, tmp);
    printf("b %s\n", tmp);
    mp_tohex((mp_int*)other_key.pubkey.x, tmp);
    printf("x %s\n", tmp);
    mp_tohex((mp_int*)other_key.pubkey.y, tmp);
    printf("y %s\n", tmp);
  }
#endif

  return err;
}

int CryptoService::calcSecret() {
  dbgprintf("calcSecret\n");
  int err;
  secret_length = sizeof(secret);
  memset(secret, 0, sizeof(secret));
  err = ECC_shared_secret(&key, &other_key, secret, &secret_length);

#ifdef DEBUG
  printf("secret ");
  print_hex(secret, secret_length);
#endif

  return err;
}

int CryptoService::writePubKey(unsigned char *buff, long unsigned int *olen) {
  int err;
  buff[0] = PARAMS;
  (*olen)--;

  err = ecc_export_openssl(buff + 1, olen, PK_PUBLIC | PK_CURVEOID, &key);
  (*olen)++;

  return err;
}

int CryptoService::decrypt(unsigned char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen) {
  int err;
  unsigned long klen = MAXBLOCKSIZE, taglen = TAG_LEN;
  unsigned char key[MAXBLOCKSIZE];
  
  unsigned char *iv = in, *tag = in + inlen-TAG_LEN;

  if (inlen < IV_LEN + TAG_LEN) return -1;

  if (is_server)
    hmac(secret, secret_length, (const unsigned char*)"server", strlen("server"), key, &klen);
  else
    hmac(secret, secret_length, (const unsigned char*)"client", strlen("client"), key, &klen);

  err = gcm_memory(find_cipher("aes"),
             key, klen,
             iv, IV_LEN,
             NULL, 0, //adata
             in+IV_LEN, inlen-IV_LEN-TAG_LEN,
             out,
             tag, &taglen,
             GCM_ENCRYPT
            );
  
  if (err == CRYPT_OK) {
    *outlen = inlen-IV_LEN-TAG_LEN;
  } else {
    *outlen = 0;
  }
  
  return err;
}

void CryptoService::writeFlag(unsigned char *buff, long unsigned int *olen) {
  int err;
  buff[0] = FLAG;

  unsigned long klen = MAXBLOCKSIZE, taglen = TAG_LEN, flaglen = strlen(CTF_FLAG);
  unsigned char client_key[MAXBLOCKSIZE], iv[IV_LEN], ct[flaglen], tag[TAG_LEN];


  hmac(secret, secret_length, (const unsigned char*)"client", strlen("client"), client_key, &klen);

  random32(iv, IV_LEN);
  err = gcm_memory(find_cipher("aes"),
             client_key, klen,
             iv, IV_LEN,
             NULL, 0, //adata
             (unsigned char*)CTF_FLAG, strlen(CTF_FLAG),
             ct,
             tag, &taglen,
             GCM_ENCRYPT
            );
  
  /*memcpy(ct, CTF_FLAG, flaglen);
  err = crypt(client_key, klen, ct, flaglen, iv, tag,  &taglen, true) ;*/

  if (err != CRYPT_OK || taglen != TAG_LEN) {
    Serial.printf("Can't write flag %s\n", error_to_string(err));
    *olen = 0;
    return;
  }

  memcpy(buff + 1, iv, IV_LEN);
  memcpy(buff + 1 + IV_LEN, ct, flaglen);
  memcpy(buff + 1 + IV_LEN + flaglen, tag, taglen);

  *olen = 1 + IV_LEN + flaglen + taglen;
}
