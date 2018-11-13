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

/**
  @file ecc_sign_hash.c
  ECC Crypto, Tom St Denis
*/

/**
  Sign a message digest
  @param in        The message digest to sign
  @param inlen     The length of the digest
  @param out       [out] The destination for the signature
  @param outlen    [in/out] The max size and resulting size of the signature
  @param prng      An active PRNG state
  @param wprng     The index of the PRNG you wish to use
  @param sigformat The format of the signature to generate (ecc_signature_type)
  @param recid     [out] The recovery ID for this signature (optional)
  @param key       A private ECC key
  @return CRYPT_OK if successful
*/
int ecc_sign_hash_ex(const unsigned char *in,  unsigned long inlen,
                     unsigned char *out, unsigned long *outlen,
                     prng_state *prng, int wprng, ecc_signature_type sigformat,
                     int *recid, const ecc_key *key)
{
   ecc_key       pubkey;
   void          *r, *s, *e, *p, *b;
   int           v = 0;
   int           err, max_iterations = LTC_PK_MAX_RETRIES;
   unsigned long pbits, pbytes, i, shift_right;
   unsigned char ch, buf[MAXBLOCKSIZE];

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* is this a private key? */
   if (key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* init the bignums */
   if ((err = mp_init_multi(&r, &s, &e, &b, NULL)) != CRYPT_OK) {
      return err;
   }

   /* get the hash and load it as a bignum into 'e' */
   p = key->dp.order;
   pbits = mp_count_bits(p);
   pbytes = (pbits+7) >> 3;
   if (pbits > inlen*8) {
      if ((err = mp_read_unsigned_bin(e, (unsigned char *)in, inlen)) != CRYPT_OK)    { goto errnokey; }
   }
   else if (pbits % 8 == 0) {
      if ((err = mp_read_unsigned_bin(e, (unsigned char *)in, pbytes)) != CRYPT_OK)   { goto errnokey; }
   }
   else {
      shift_right = 8 - pbits % 8;
      for (i=0, ch=0; i<pbytes; i++) {
        buf[i] = ch;
        ch = (in[i] << (8-shift_right));
        buf[i] = buf[i] ^ (in[i] >> shift_right);
      }
      if ((err = mp_read_unsigned_bin(e, (unsigned char *)buf, pbytes)) != CRYPT_OK)  { goto errnokey; }
   }

   /* make up a key and export the public copy */
   do {
      if ((err = ecc_copy_curve(key, &pubkey)) != CRYPT_OK)                { goto errnokey; }
      if ((err = ecc_generate_key(prng, wprng, &pubkey)) != CRYPT_OK)      { goto errnokey; }

      /* find r = x1 mod n */
      if ((err = mp_mod(pubkey.pubkey.x, p, r)) != CRYPT_OK)               { goto error; }

      if (recid || sigformat==LTC_ECCSIG_ETH27) {
         /* find recovery ID (if needed) */
         v = 0;
         if (mp_copy(pubkey.pubkey.x, s) != CRYPT_OK)                      { goto error; }
         while (mp_cmp_d(s, 0) == LTC_MP_GT && mp_cmp(s, p) != LTC_MP_LT) {
            /* Compute x1 div n... this will almost never be reached for curves with order 1 */
            v += 2;
            if ((err = mp_sub(s, p, s)) != CRYPT_OK)                       { goto error; }
         }
         if (mp_isodd(pubkey.pubkey.y)) v += 1;
      }

      if (mp_iszero(r) == LTC_MP_YES) {
         ecc_free(&pubkey);
      } else {
         if ((err = rand_bn_upto(b, p, prng, wprng)) != CRYPT_OK)          { goto error; } /* b = blinding value */
         /* find s = (e + xr)/k */
         if ((err = mp_mulmod(pubkey.k, b, p, pubkey.k)) != CRYPT_OK)      { goto error; } /* k = kb */
         if ((err = mp_invmod(pubkey.k, p, pubkey.k)) != CRYPT_OK)         { goto error; } /* k = 1/kb */
         if ((err = mp_mulmod(key->k, r, p, s)) != CRYPT_OK)               { goto error; } /* s = xr */
         if ((err = mp_mulmod(pubkey.k, s, p, s)) != CRYPT_OK)             { goto error; } /* s = xr/kb */
         if ((err = mp_mulmod(pubkey.k, e, p, e)) != CRYPT_OK)             { goto error; } /* e = e/kb */
         if ((err = mp_add(e, s, s)) != CRYPT_OK)                          { goto error; } /* s = e/kb + xr/kb */
         if ((err = mp_mulmod(s, b, p, s)) != CRYPT_OK)                    { goto error; } /* s = b(e/kb + xr/kb) = (e + xr)/k */
         ecc_free(&pubkey);
         if (mp_iszero(s) == LTC_MP_NO) {
            break;
         }
      }
   } while (--max_iterations > 0);

   if (max_iterations == 0) {
      goto errnokey;
   }

   if (recid) *recid = v;

   if (sigformat == LTC_ECCSIG_ANSIX962) {
      /* store as ASN.1 SEQUENCE { r, s -- integer } */
      err = der_encode_sequence_multi(out, outlen,
                               LTC_ASN1_INTEGER, 1UL, r,
                               LTC_ASN1_INTEGER, 1UL, s,
                               LTC_ASN1_EOL, 0UL, NULL);
   }
   else if (sigformat == LTC_ECCSIG_RFC7518) {
      /* RFC7518 format - raw (r,s) */
      if (*outlen < 2*pbytes) { err = CRYPT_MEM; goto errnokey; }
      zeromem(out, 2*pbytes);
      i = mp_unsigned_bin_size(r);
      if ((err = mp_to_unsigned_bin(r, out + (pbytes - i)))   != CRYPT_OK) { goto errnokey; }
      i = mp_unsigned_bin_size(s);
      if ((err = mp_to_unsigned_bin(s, out + (2*pbytes - i))) != CRYPT_OK) { goto errnokey; }
      *outlen = 2*pbytes;
      err = CRYPT_OK;
   }
   else if (sigformat == LTC_ECCSIG_ETH27) {
      /* Ethereum (v,r,s) format */
      if (pk_oid_cmp_with_ulong("1.3.132.0.10", key->dp.oid, key->dp.oidlen) != CRYPT_OK) {
         /* Only valid for secp256k1 - OID 1.3.132.0.10 */
         err = CRYPT_ERROR; goto errnokey;
      }
      if (*outlen < 65) { err = CRYPT_MEM; goto errnokey; }
      zeromem(out, 65);
      i = mp_unsigned_bin_size(r);
      if ((err = mp_to_unsigned_bin(r, out + 32 - i)) != CRYPT_OK) { goto errnokey; }
      i = mp_unsigned_bin_size(s);
      if ((err = mp_to_unsigned_bin(s, out + 64 - i)) != CRYPT_OK) { goto errnokey; }
      out[64] = (unsigned char)(v + 27); /* Recovery ID is 27/28 for Ethereum */
      *outlen = 65;
      err = CRYPT_OK;
   }
#ifdef LTC_SSH
   else if (sigformat == LTC_ECCSIG_RFC5656) {
      /* Get identifier string */
      char name[64];
      unsigned long namelen = sizeof(name);
      if ((err = ecc_ssh_ecdsa_encode_name(name, &namelen, key)) != CRYPT_OK) { goto errnokey; }

      /* Store as SSH data sequence, per RFC4251 */
      err = ssh_encode_sequence_multi(out, outlen,
                                      LTC_SSHDATA_STRING, name,
                                      LTC_SSHDATA_MPINT,  r,
                                      LTC_SSHDATA_MPINT,  s,
                                      LTC_SSHDATA_EOL,    NULL);
   }
#endif
   else {
      /* Unknown signature format */
      err = CRYPT_ERROR;
      goto error;
   }

   goto errnokey;
error:
   ecc_free(&pubkey);
errnokey:
   mp_clear_multi(r, s, e, b, NULL);
   return err;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
