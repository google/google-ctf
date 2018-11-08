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

extern "C" {
  ecc_point *ltc_ecc_new_point(void);
  void       ltc_ecc_del_point(ecc_point *p);
}

int ECC_shared_secret(const ecc_key *private_key, const ecc_key *public_key,
                      unsigned char *out, unsigned long *outlen)
{
   unsigned long  x;
   ecc_point     *result;
   void          *prime, *a;
   int            err;

   LTC_ARGCHK(private_key != NULL);
   LTC_ARGCHK(public_key  != NULL);
   LTC_ARGCHK(out         != NULL);
   LTC_ARGCHK(outlen      != NULL);

   /* type valid? */
   if (private_key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* make new point */
   result = ltc_ecc_new_point();
   if (result == NULL) {
      return CRYPT_MEM;
   }



   /* Oops... */
   /*prime = private_key->dp.prime;
   a     = private_key->dp.A;*/
   prime = public_key->dp.prime;
   a     = public_key->dp.A;

   if ((err = ltc_mp.ecc_ptmul(private_key->k, &public_key->pubkey, result, a, prime, 1)) != CRYPT_OK)   { goto done; }

   x = (unsigned long)mp_unsigned_bin_size((const mp_int*)prime);
   if (*outlen < x) {
      *outlen = x;
      err = CRYPT_BUFFER_OVERFLOW;
      goto done;
   }
   zeromem(out, x);
   if ((err = mp_to_unsigned_bin((const mp_int*)result->x, out + (x - mp_unsigned_bin_size((const mp_int*)result->x))))   != CRYPT_OK) { goto done; }

   err     = CRYPT_OK;
   *outlen = x;
done:
   ltc_ecc_del_point(result);
   return err;
}
