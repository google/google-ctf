/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

static const struct {
   const char *OID;
   const char *names[6];
} _curve_names[] = {
#ifdef LTC_ECC_SECP112R1
   {
      "1.3.132.0.6", { "SECP112R1", "ECC-112", NULL }
   },
#endif
#ifdef LTC_ECC_SECP112R2
   {
      "1.3.132.0.7", { "SECP112R2", NULL }
   },
#endif
#ifdef LTC_ECC_SECP128R1
   {
      "1.3.132.0.28", { "SECP128R1", "ECC-128", NULL }
   },
#endif
#ifdef LTC_ECC_SECP128R2
   {
      "1.3.132.0.29", { "SECP128R2", NULL }
   },
#endif
#ifdef LTC_ECC_SECP160R1
   {
      "1.3.132.0.8", { "SECP160R1", "ECC-160", NULL }
   },
#endif
#ifdef LTC_ECC_SECP160R2
   {
      "1.3.132.0.30", { "SECP160R2", NULL }
   },
#endif
#ifdef LTC_ECC_SECP160K1
   {
      "1.3.132.0.9", { "SECP160K1", NULL }
   },
#endif
#ifdef LTC_ECC_SECP192R1
   {
      "1.2.840.10045.3.1.1", { "SECP192R1", "NISTP192", "PRIME192V1", "ECC-192", "P-192", NULL }
   },
#endif
#ifdef LTC_ECC_PRIME192V2
   {
      "1.2.840.10045.3.1.2", { "PRIME192V2", NULL }
   },
#endif
#ifdef LTC_ECC_PRIME192V3
   {
      "1.2.840.10045.3.1.3", { "PRIME192V3", NULL }
   },
#endif
#ifdef LTC_ECC_SECP192K1
   {
      "1.3.132.0.31", { "SECP192K1", NULL }
   },
#endif
#ifdef LTC_ECC_SECP224R1
   {
      "1.3.132.0.33", { "SECP224R1", "NISTP224", "ECC-224", "P-224", NULL }
   },
#endif
#ifdef LTC_ECC_SECP224K1
   {
      "1.3.132.0.32", { "SECP224K1", NULL }
   },
#endif
#ifdef LTC_ECC_SECP256R1
   {
      "1.2.840.10045.3.1.7", { "SECP256R1", "NISTP256", "PRIME256V1", "ECC-256", "P-256", NULL }
   },
#endif
#ifdef LTC_ECC_SECP256K1
   {
      "1.3.132.0.10", { "SECP256K1", NULL }
   },
#endif
#ifdef LTC_ECC_SECP384R1
   {
      "1.3.132.0.34", { "SECP384R1", "NISTP384", "ECC-384", "P-384", NULL }
   },
#endif
#ifdef LTC_ECC_SECP521R1
   {
      "1.3.132.0.35", { "SECP521R1", "NISTP521", "ECC-521", "P-521", NULL }
   },
#endif
#ifdef LTC_ECC_PRIME239V1
   {
      "1.2.840.10045.3.1.4", { "PRIME239V1", NULL }
   },
#endif
#ifdef LTC_ECC_PRIME239V2
   {
      "1.2.840.10045.3.1.5", { "PRIME239V2", NULL }
   },
#endif
#ifdef LTC_ECC_PRIME239V3
   {
      "1.2.840.10045.3.1.6", { "PRIME239V3", NULL }
   },
#endif
#ifdef LTC_ECC_BRAINPOOLP160R1
   {
      "1.3.36.3.3.2.8.1.1.1", { "BRAINPOOLP160R1", NULL }
   },
#endif
#ifdef LTC_ECC_BRAINPOOLP192R1
   {
      "1.3.36.3.3.2.8.1.1.3", { "BRAINPOOLP192R1", NULL }
   },
#endif
#ifdef LTC_ECC_BRAINPOOLP224R1
   {
      "1.3.36.3.3.2.8.1.1.5", { "BRAINPOOLP224R1", NULL }
   },
#endif
#ifdef LTC_ECC_BRAINPOOLP256R1
   {
      "1.3.36.3.3.2.8.1.1.7", { "BRAINPOOLP256R1", NULL }
   },
#endif
#ifdef LTC_ECC_BRAINPOOLP320R1
   {
      "1.3.36.3.3.2.8.1.1.9", { "BRAINPOOLP320R1", NULL }
   },
#endif
#ifdef LTC_ECC_BRAINPOOLP384R1
   {
      "1.3.36.3.3.2.8.1.1.11", { "BRAINPOOLP384R1", NULL }
   },
#endif
#ifdef LTC_ECC_BRAINPOOLP512R1
   {
      "1.3.36.3.3.2.8.1.1.13", { "BRAINPOOLP512R1", NULL }
   },
#endif
#ifdef LTC_ECC_BRAINPOOLP160T1
   {
      "1.3.36.3.3.2.8.1.1.2", { "BRAINPOOLP160T1", NULL }
   },
#endif
#ifdef LTC_ECC_BRAINPOOLP192T1
   {
      "1.3.36.3.3.2.8.1.1.4", { "BRAINPOOLP192T1", NULL }
   },
#endif
#ifdef LTC_ECC_BRAINPOOLP224T1
   {
      "1.3.36.3.3.2.8.1.1.6", { "BRAINPOOLP224T1", NULL }
   },
#endif
#ifdef LTC_ECC_BRAINPOOLP256T1
   {
      "1.3.36.3.3.2.8.1.1.8", { "BRAINPOOLP256T1", NULL }
   },
#endif
#ifdef LTC_ECC_BRAINPOOLP320T1
   {
      "1.3.36.3.3.2.8.1.1.10", { "BRAINPOOLP320T1", NULL }
   },
#endif
#ifdef LTC_ECC_BRAINPOOLP384T1
   {
      "1.3.36.3.3.2.8.1.1.12", { "BRAINPOOLP384T1", NULL }
   },
#endif
#ifdef LTC_ECC_BRAINPOOLP512T1
   {
      "1.3.36.3.3.2.8.1.1.14", { "BRAINPOOLP512T1", NULL }
   },
#endif
   {
      NULL, { NULL }
   }
};

/* case-insensitive match + ignore '-', '_', ' ' */
static int _name_match(const char *left, const char *right)
{
   char lc_r, lc_l;

   while ((*left != '\0') && (*right != '\0')) {
      while ((*left  == ' ') || (*left  == '-') || (*left  == '_')) left++;
      while ((*right == ' ') || (*right == '-') || (*right == '_')) right++;
      if (*left == '\0' || *right == '\0') break;
      lc_r = *right;
      lc_l = *left;
      if ((lc_r >= 'A') && (lc_r <= 'Z')) lc_r += 32;
      if ((lc_l >= 'A') && (lc_l <= 'Z')) lc_l += 32;
      if (lc_l != lc_r) return 0;
      left++;
      right++;
   }

   if ((*left == '\0') && (*right == '\0')) return 1;
   return 0;
}

int ecc_find_curve(const char *name_or_oid, const ltc_ecc_curve **cu)
{
   int i, j;
   const char *OID = NULL;

   LTC_ARGCHK(cu != NULL);
   LTC_ARGCHK(name_or_oid != NULL);

   *cu = NULL;

   for (i = 0; _curve_names[i].OID != NULL && !OID; i++) {
      if (XSTRCMP(_curve_names[i].OID, name_or_oid) == 0) {
         OID = _curve_names[i].OID;
      }
      for (j = 0; _curve_names[i].names[j] != NULL && !OID; j++) {
         if (_name_match(_curve_names[i].names[j], name_or_oid)) {
            OID = _curve_names[i].OID;
         }
      }
   }

   if (OID != NULL) {
      for (i = 0; ltc_ecc_curves[i].prime != NULL; i++) {
         if (XSTRCMP(ltc_ecc_curves[i].OID, OID) == 0) {
            *cu = &ltc_ecc_curves[i];
            return CRYPT_OK;
         }
      }
   }

   return CRYPT_INVALID_ARG; /* not found */
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
