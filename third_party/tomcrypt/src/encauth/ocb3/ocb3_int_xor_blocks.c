/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/**
   @file ocb3_int_xor_blocks.c
   OCB implementation, INTERNAL ONLY helper, by Karel Miko
*/
#include "tomcrypt_private.h"

#ifdef LTC_OCB3_MODE

/**
   Compute xor for two blocks of bytes 'out = block_a XOR block_b' (internal function)
   @param out        The block of bytes (output)
   @param block_a    The block of bytes (input)
   @param block_b    The block of bytes (input)
   @param block_len  The size of block_a, block_b, out
*/
void ocb3_int_xor_blocks(unsigned char *out, const unsigned char *block_a, const unsigned char *block_b, unsigned long block_len)
{
   int x;
   if (out == block_a) {
     for (x = 0; x < (int)block_len; x++) out[x] ^= block_b[x];
   }
   else {
     for (x = 0; x < (int)block_len; x++) out[x] = block_a[x] ^ block_b[x];
   }
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
