/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt_private.h"

int pk_oid_str_to_num(const char *OID, unsigned long *oid, unsigned long *oidlen)
{
   unsigned long i, j, limit, OID_len, oid_j;

   LTC_ARGCHK(oidlen != NULL);

   limit = *oidlen;
   *oidlen = 0; /* make sure that we return zero oidlen on error */
   for (i = 0; i < limit; i++) oid[i] = 0;

   if (OID == NULL) return CRYPT_OK;

   OID_len = strlen(OID);
   if (OID_len == 0) return CRYPT_OK;

   for (i = 0, j = 0; i < OID_len; i++) {
      if (OID[i] == '.') {
         if (++j >= limit) continue;
      }
      else if ((OID[i] >= '0') && (OID[i] <= '9')) {
         if ((j >= limit) || (oid == NULL)) continue;
         oid_j = oid[j];
         oid[j] = oid[j] * 10 + (OID[i] - '0');
         if (oid[j] < oid_j) return CRYPT_OVERFLOW;
      }
      else {
         return CRYPT_ERROR;
      }
   }
   if (j == 0) return CRYPT_ERROR;
   if (j >= limit) {
      *oidlen = j;
      return CRYPT_BUFFER_OVERFLOW;
   }
   *oidlen = j + 1;
   return CRYPT_OK;
}

int pk_oid_num_to_str(const unsigned long *oid, unsigned long oidlen, char *OID, unsigned long *outlen)
{
   int i;
   unsigned long j, k;
   char tmp[256] = { 0 };

   LTC_ARGCHK(oid != NULL);
   LTC_ARGCHK(OID != NULL);
   LTC_ARGCHK(outlen != NULL);

   for (i = oidlen - 1, k = 0; i >= 0; i--) {
      j = oid[i];
      if (j == 0) {
         tmp[k] = '0';
         if (++k >= sizeof(tmp)) return CRYPT_ERROR;
      }
      else {
         while (j > 0) {
            tmp[k] = '0' + (j % 10);
            if (++k >= sizeof(tmp)) return CRYPT_ERROR;
            j /= 10;
         }
      }
      if (i > 0) {
        tmp[k] = '.';
        if (++k >= sizeof(tmp)) return CRYPT_ERROR;
      }
   }
   if (*outlen < k + 1) {
      *outlen = k + 1;
      return CRYPT_BUFFER_OVERFLOW;
   }
   for (j = 0; j < k; j++) OID[j] = tmp[k - j - 1];
   OID[k] = '\0';
   *outlen = k; /* the length without terminating NUL byte */
   return CRYPT_OK;
}

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
