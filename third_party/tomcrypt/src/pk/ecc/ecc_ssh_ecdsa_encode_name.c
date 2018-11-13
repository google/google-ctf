/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

/**
   @file ecc_ssh_ecdsa_encode_name.c
   Curve/OID to SSH+ECDSA name string mapping per RFC5656
   Russ Williams
*/

/**
  Curve/OID to SSH+ECDSA name string mapping
  @param buffer    [out] The destination for the name
  @param buflen    [in/out] The max size and resulting size (including terminator) of the name
  @param key       A public or private ECC key
  @return CRYPT_OK if successful
*/
int ecc_ssh_ecdsa_encode_name(char *buffer, unsigned long *buflen, const ecc_key *key)
{
   char oidstr[64];
   unsigned long oidlen = sizeof(oidstr);
   unsigned long size = 0;
   int err;

   LTC_ARGCHK(buffer != NULL);
   LTC_ARGCHK(buflen != NULL);
   LTC_ARGCHK(key != NULL);

   /* Get the OID of the curve */
   if ((err = ecc_get_oid_str(oidstr, &oidlen, key)) != CRYPT_OK) goto error;

   /* Check for three named curves: nistp256, nistp384, nistp521 */
   if (XSTRCMP("1.2.840.10045.3.1.7", oidstr) == 0) {
      /* nistp256 - secp256r1 - OID 1.2.840.10045.3.1.7 */
      size = snprintf(buffer, *buflen, "ecdsa-sha2-nistp256");
   }
   else if (XSTRCMP("1.3.132.0.34", oidstr) == 0) {
      /* nistp384 - secp384r1 - OID 1.3.132.0.34 */
      size = snprintf(buffer, *buflen, "ecdsa-sha2-nistp384");
   }
   else if (XSTRCMP("1.3.132.0.35", oidstr) == 0) {
      /* nistp521 - secp521r1 - OID 1.3.132.0.35 */
      size = snprintf(buffer, *buflen, "ecdsa-sha2-nistp521");
   } else {
      /* Otherwise we use the OID... */
      size = snprintf(buffer, *buflen, "ecdsa-sha2-%s", oidstr);
   }

   /* snprintf returns size that would have been written, but limits to buflen-1 chars plus terminator */
   if (size >= *buflen) {
      err = CRYPT_BUFFER_OVERFLOW;
   } else {
      err = CRYPT_OK;
   }
   *buflen = size + 1; /* the string length + NUL byte */

error:
   return err;
}


/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
