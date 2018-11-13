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
  @file base64_decode.c
  Compliant base64 code donated by Wayne Scott (wscott@bitmover.com)
  base64 URL Safe variant (RFC 4648 section 5) by Karel Miko
*/


#if defined(LTC_BASE64) || defined (LTC_BASE64_URL)

/* 253 - ignored in "relaxed" + "insane" mode: TAB(9), CR(13), LF(10), space(32)
 * 254 - padding character '=' (allowed only at the end)
 * 255 - ignored in "insane" mode, but not allowed in "relaxed" + "strict" mode
 */

#if defined(LTC_BASE64)
static const unsigned char map_base64[256] = {
255, 255, 255, 255, 255, 255, 255, 255, 255, 253, 253, 255,
255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 253, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,
 52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255,
255, 254, 255, 255, 255,   0,   1,   2,   3,   4,   5,   6,
  7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,
 19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,
 37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
 49,  50,  51, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255 };
#endif /* LTC_BASE64 */

static const unsigned char map_base64url[] = {
#if defined(LTC_BASE64_URL)
255, 255, 255, 255, 255, 255, 255, 255, 255, 253, 253, 255,
255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 253, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255,  62, 255, 255,
 52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255,
255, 254, 255, 255, 255,   0,   1,   2,   3,   4,   5,   6,
  7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,
 19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255,  63,
255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,
 37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
 49,  50,  51, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255
#endif /* LTC_BASE64_URL */
};

enum {
   insane = 0,
   strict = 1,
   relaxed = 2
};

static int _base64_decode_internal(const char *in,  unsigned long inlen,
                                 unsigned char *out, unsigned long *outlen,
                           const unsigned char *map, int mode)
{
   unsigned long t, x, y, z;
   unsigned char c;
   int           g;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   g = 0; /* '=' counter */
   for (x = y = z = t = 0; x < inlen; x++) {
       if ((in[x] == 0) && (x == (inlen - 1)) && (mode != strict)) {
          continue; /* allow the last byte to be NUL (relaxed+insane) */
       }
       c = map[(unsigned char)in[x]&0xFF];
       if (c == 254) {
          g++;
          continue;
       }
       if (c == 253) {
          if (mode == strict) {
             return CRYPT_INVALID_PACKET;
          }
          continue; /* allow to ignore white-spaces (relaxed+insane) */
       }
       if (c == 255) {
          if (mode == insane) {
             continue; /* allow to ignore invalid garbage (insane) */
          }
          return CRYPT_INVALID_PACKET;
       }
       if ((g > 0) && (mode != insane)) {
          /* we only allow '=' to be at the end (strict+relaxed) */
          return CRYPT_INVALID_PACKET;
       }

       t = (t<<6)|c;

       if (++y == 4) {
          if (z + 3 > *outlen) return CRYPT_BUFFER_OVERFLOW;
          out[z++] = (unsigned char)((t>>16)&255);
          out[z++] = (unsigned char)((t>>8)&255);
          out[z++] = (unsigned char)(t&255);
          y = t = 0;
       }
   }

   if (y != 0) {
      if (y == 1) return CRYPT_INVALID_PACKET;
      if (((y + g) != 4) && (mode == strict) && (map != map_base64url)) return CRYPT_INVALID_PACKET;
      t = t << (6 * (4 - y));
      if (z + y - 1 > *outlen) return CRYPT_BUFFER_OVERFLOW;
      if (y >= 2) out[z++] = (unsigned char) ((t >> 16) & 255);
      if (y == 3) out[z++] = (unsigned char) ((t >> 8) & 255);
   }
   *outlen = z;
   return CRYPT_OK;
}

#if defined(LTC_BASE64)
/**
   Dangerously relaxed base64 decode a block of memory
   @param in       The base64 data to decode
   @param inlen    The length of the base64 data
   @param out      [out] The destination of the binary decoded data
   @param outlen   [in/out] The max size and resulting size of the decoded data
   @return CRYPT_OK if successful
*/
int base64_decode(const char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen)
{
    return _base64_decode_internal(in, inlen, out, outlen, map_base64, insane);
}

/**
   Strict base64 decode a block of memory
   @param in       The base64 data to decode
   @param inlen    The length of the base64 data
   @param out      [out] The destination of the binary decoded data
   @param outlen   [in/out] The max size and resulting size of the decoded data
   @return CRYPT_OK if successful
*/
int base64_strict_decode(const char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen)
{
   return _base64_decode_internal(in, inlen, out, outlen, map_base64, strict);
}

/**
   Sane base64 decode a block of memory
   @param in       The base64 data to decode
   @param inlen    The length of the base64 data
   @param out      [out] The destination of the binary decoded data
   @param outlen   [in/out] The max size and resulting size of the decoded data
   @return CRYPT_OK if successful
*/
int base64_sane_decode(const char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen)
{
   return _base64_decode_internal(in, inlen, out, outlen, map_base64, relaxed);
}
#endif /* LTC_BASE64 */

#if defined(LTC_BASE64_URL)
/**
   Dangerously relaxed base64 (URL Safe, RFC 4648 section 5) decode a block of memory
   @param in       The base64 data to decode
   @param inlen    The length of the base64 data
   @param out      [out] The destination of the binary decoded data
   @param outlen   [in/out] The max size and resulting size of the decoded data
   @return CRYPT_OK if successful
*/
int base64url_decode(const char *in,  unsigned long inlen,
                           unsigned char *out, unsigned long *outlen)
{
    return _base64_decode_internal(in, inlen, out, outlen, map_base64url, insane);
}

/**
   Strict base64 (URL Safe, RFC 4648 section 5) decode a block of memory
   @param in       The base64 data to decode
   @param inlen    The length of the base64 data
   @param out      [out] The destination of the binary decoded data
   @param outlen   [in/out] The max size and resulting size of the decoded data
   @return CRYPT_OK if successful
*/
int base64url_strict_decode(const char *in,  unsigned long inlen,
                           unsigned char *out, unsigned long *outlen)
{
    return _base64_decode_internal(in, inlen, out, outlen, map_base64url, strict);
}

/**
   Sane base64 (URL Safe, RFC 4648 section 5) decode a block of memory
   @param in       The base64 data to decode
   @param inlen    The length of the base64 data
   @param out      [out] The destination of the binary decoded data
   @param outlen   [in/out] The max size and resulting size of the decoded data
   @return CRYPT_OK if successful
*/
int base64url_sane_decode(const char *in,  unsigned long inlen,
                           unsigned char *out, unsigned long *outlen)
{
    return _base64_decode_internal(in, inlen, out, outlen, map_base64url, relaxed);
}
#endif /* LTC_BASE64_URL */

#endif


/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
