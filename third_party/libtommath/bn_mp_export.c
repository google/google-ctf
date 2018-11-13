#include "tommath_private.h"
#ifdef BN_MP_EXPORT_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is a library that provides multiple-precision
 * integer arithmetic as well as number theoretic functionality.
 *
 * The library was designed directly after the MPI library by
 * Michael Fromberger but has been written from scratch with
 * additional optimizations in place.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/* based on gmp's mpz_export.
 * see http://gmplib.org/manual/Integer-Import-and-Export.html
 */
int mp_export(void *rop, size_t *countp, int order, size_t size,
              int endian, size_t nails, const mp_int *op)
{
   int result;
   size_t odd_nails, nail_bytes, i, j, bits, count;
   unsigned char odd_nail_mask;

   mp_int t;

   if ((result = mp_init_copy(&t, op)) != MP_OKAY) {
      return result;
   }

   if (endian == 0) {
      union {
         unsigned int i;
         char c[4];
      } lint;
      lint.i = 0x01020304;

      endian = (lint.c[0] == '\x04') ? -1 : 1;
   }

   odd_nails = (nails % 8u);
   odd_nail_mask = 0xff;
   for (i = 0; i < odd_nails; ++i) {
      odd_nail_mask ^= (unsigned char)(1u << (7u - i));
   }
   nail_bytes = nails / 8u;

   bits = (size_t)mp_count_bits(&t);
   count = (bits / ((size * 8u) - nails)) + (((bits % ((size * 8u) - nails)) != 0u) ? 1u : 0u);

   for (i = 0; i < count; ++i) {
      for (j = 0; j < size; ++j) {
         unsigned char *byte = (unsigned char *)rop +
                               (((order == -1) ? i : ((count - 1u) - i)) * size) +
                               ((endian == -1) ? j : ((size - 1u) - j));

         if (j >= (size - nail_bytes)) {
            *byte = 0;
            continue;
         }

         *byte = (unsigned char)((j == ((size - nail_bytes) - 1u)) ? (t.dp[0] & odd_nail_mask) : (t.dp[0] & 0xFFuL));

         if ((result = mp_div_2d(&t, (j == ((size - nail_bytes) - 1u)) ? (int)(8u - odd_nails) : 8, &t, NULL)) != MP_OKAY) {
            mp_clear(&t);
            return result;
         }
      }
   }

   mp_clear(&t);

   if (countp != NULL) {
      *countp = count;
   }

   return MP_OKAY;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  8b9f98baa16b21e1612ac6746273febb74150a6f */
/* commit time: 2018-09-23 21:37:58 +0200 */
