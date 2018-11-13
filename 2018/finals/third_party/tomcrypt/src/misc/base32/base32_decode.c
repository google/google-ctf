/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt_private.h"

#ifdef LTC_BASE32

/**
   Base32 decode a buffer
   @param in       The Base32 data to decode
   @param inlen    The length of the Base32 data
   @param out      [out] The destination of the binary decoded data
   @param outlen   [in/out] The max size and resulting size of the decoded data
   @param id       Alphabet to use BASE32_RFC4648, BASE32_BASE32HEX, BASE32_ZBASE32 or BASE32_CROCKFORD
   @return CRYPT_OK if successful
*/
int base32_decode(const          char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen,
                        base32_alphabet id)
{
   unsigned long x;
   int y = 0;
   ulong64 t = 0;
   char c;
   const unsigned char *map;
   const unsigned char tables[4][43] = {
      {  /* id = BASE32_RFC4648 : ABCDEFGHIJKLMNOPQRSTUVWXYZ234567 */
         99/*0*/,99/*1*/,26/*2*/,27/*3*/,28/*4*/,29/*5*/,30/*6*/,31/*7*/,99/*8*/,99/*9*/,
         99/*:*/,99/*;*/,99/*<*/,99/*=*/,99/*>*/,99/*?*/,99/*@*/,
          0/*A*/, 1/*B*/, 2/*C*/, 3/*D*/, 4/*E*/, 5/*F*/, 6/*G*/, 7/*H*/, 8/*I*/, 9/*J*/,10/*K*/,11/*L*/,12/*M*/,
         13/*N*/,14/*O*/,15/*P*/,16/*Q*/,17/*R*/,18/*S*/,19/*T*/,20/*U*/,21/*V*/,22/*W*/,23/*X*/,24/*Y*/,25/*Z*/
      },
      {  /* id = BASE32_BASE32HEX : 0123456789ABCDEFGHIJKLMNOPQRSTUV */
           0/*0*/, 1/*1*/, 2/*2*/, 3/*3*/, 4/*4*/, 5/*5*/, 6/*6*/, 7/*7*/, 8/*8*/, 9/*9*/,
          99/*:*/,99/*;*/,99/*<*/,99/*=*/,99/*>*/,99/*?*/,99/*@*/,
          10/*A*/,11/*B*/,12/*C*/,13/*D*/,14/*E*/,15/*F*/,16/*G*/,17/*H*/,18/*I*/,19/*J*/,20/*K*/,21/*L*/,22/*M*/,
          23/*N*/,24/*O*/,25/*P*/,26/*Q*/,27/*R*/,28/*S*/,29/*T*/,30/*U*/,31/*V*/,99/*W*/,99/*X*/,99/*Y*/,99/*Z*/
      },
      {  /* id = BASE32_ZBASE32 : YBNDRFG8EJKMCPQXOT1UWISZA345H769 */
         99/*0*/,18/*1*/,99/*2*/,25/*3*/,26/*4*/,27/*5*/,30/*6*/,29/*7*/, 7/*8*/,31/*9*/,
         99/*:*/,99/*;*/,99/*<*/,99/*=*/,99/*>*/,99/*?*/,99/*@*/,
         24/*A*/, 1/*B*/,12/*C*/, 3/*D*/, 8/*E*/, 5/*F*/, 6/*G*/,28/*H*/,21/*I*/, 9/*J*/,10/*K*/,99/*L*/,11/*M*/,
          2/*N*/,16/*O*/,13/*P*/,14/*Q*/, 4/*R*/,22/*S*/,17/*T*/,19/*U*/,99/*V*/,20/*W*/,15/*X*/, 0/*Y*/,23/*Z*/
      },
      {  /* id = BASE32_CROCKFORD : 0123456789ABCDEFGHJKMNPQRSTVWXYZ + O=>0 + IL=>1 */
          0/*0*/, 1/*1*/, 2/*2*/, 3/*3*/, 4/*4*/, 5/*5*/, 6/*6*/, 7/*7*/, 8/*8*/, 9/*9*/,
         99/*:*/,99/*;*/,99/*<*/,99/*=*/,99/*>*/,99/*?*/,99/*@*/,
         10/*A*/,11/*B*/,12/*C*/,13/*D*/,14/*E*/,15/*F*/,16/*G*/,17/*H*/, 1/*I*/,18/*J*/,19/*K*/, 1/*L*/,20/*M*/,
         21/*N*/, 0/*O*/,22/*P*/,23/*Q*/,24/*R*/,25/*S*/,26/*T*/,99/*U*/,27/*V*/,28/*W*/,29/*X*/,30/*Y*/,31/*Z*/
      }
   };

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(id >= BASE32_RFC4648);
   LTC_ARGCHK(id <= BASE32_CROCKFORD);

   /* ignore all trailing = */
   while (inlen > 0 && in[inlen-1] == '=') inlen--;

   /* no input, nothing to do */
   if (inlen == 0) {
      *outlen = 0;
      return CRYPT_OK;
   }

   /* check the size of output buffer */
   x = (inlen * 5) / 8;
   if (*outlen < x) {
      *outlen = x;
      return CRYPT_BUFFER_OVERFLOW;
   }
   *outlen = x;

   /* check input data length */
   x = inlen % 8;
   if (x == 1 || x == 3 || x == 6) {
      return CRYPT_INVALID_PACKET;
   }

   map = tables[id];
   for (x = 0; x < inlen; x++) {
      c = in[x];
      /* convert to upper case */
      if ((c >= 'a') && (c <= 'z')) c -= 32;
      if (c < '0' || c > 'Z' || map[c-'0'] > 31) {
         return CRYPT_INVALID_PACKET;
      }
      t = (t<<5) | map[c-'0'];
      if (++y == 8) {
         *out++ = (unsigned char)((t>>32) & 255);
         *out++ = (unsigned char)((t>>24) & 255);
         *out++ = (unsigned char)((t>>16) & 255);
         *out++ = (unsigned char)((t>> 8) & 255);
         *out++ = (unsigned char)( t      & 255);
         y = 0;
         t = 0;
      }
   }
   if (y > 0) {
      t = t << (5 * (8 - y));
      if (y >= 2) *out++ = (unsigned char)((t>>32) & 255);
      if (y >= 4) *out++ = (unsigned char)((t>>24) & 255);
      if (y >= 5) *out++ = (unsigned char)((t>>16) & 255);
      if (y >= 7) *out++ = (unsigned char)((t>> 8) & 255);
   }
   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
