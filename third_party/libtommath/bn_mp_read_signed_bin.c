#include "tommath_private.h"
#ifdef BN_MP_READ_SIGNED_BIN_C
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

/* read signed bin, big endian, first byte is 0==positive or 1==negative */
int mp_read_signed_bin(mp_int *a, const unsigned char *b, int c)
{
   int     res;

   /* read magnitude */
   if ((res = mp_read_unsigned_bin(a, b + 1, c - 1)) != MP_OKAY) {
      return res;
   }

   /* first byte is 0 for positive, non-zero for negative */
   if (b[0] == (unsigned char)0) {
      a->sign = MP_ZPOS;
   } else {
      a->sign = MP_NEG;
   }

   return MP_OKAY;
}
#endif

/* ref:         HEAD -> develop */
/* git commit:  8b9f98baa16b21e1612ac6746273febb74150a6f */
/* commit time: 2018-09-23 21:37:58 +0200 */
