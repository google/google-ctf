#include "tommath_private.h"
#ifdef BN_MP_RAND_C
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

/* First the OS-specific special cases
 * - *BSD
 * - Windows
 */
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
#define MP_ARC4RANDOM
#define MP_GEN_RANDOM_MAX     0xffffffffu
#define MP_GEN_RANDOM_SHIFT   32

static int s_read_arc4random(mp_digit *p)
{
   mp_digit d = 0, msk = 0;
   do {
      d <<= MP_GEN_RANDOM_SHIFT;
      d |= ((mp_digit) arc4random());
      msk <<= MP_GEN_RANDOM_SHIFT;
      msk |= (MP_MASK & MP_GEN_RANDOM_MAX);
   } while ((MP_MASK & msk) != MP_MASK);
   *p = d;
   return MP_OKAY;
}
#endif

#if defined(_WIN32) || defined(_WIN32_WCE)
#define MP_WIN_CSP

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0400
#endif
#ifdef _WIN32_WCE
#define UNDER_CE
#define ARM
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

static HCRYPTPROV hProv = 0;

static void s_cleanup_win_csp(void)
{
   CryptReleaseContext(hProv, 0);
   hProv = 0;
}

static int s_read_win_csp(mp_digit *p)
{
   int ret = -1;
   if (hProv == 0) {
      if (!CryptAcquireContext(&hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL,
                               (CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET)) &&
          !CryptAcquireContext(&hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL,
                               CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET | CRYPT_NEWKEYSET)) {
         hProv = 0;
         return ret;
      }
      atexit(s_cleanup_win_csp);
   }
   if (CryptGenRandom(hProv, sizeof(*p), (void *)p) == TRUE) {
      ret = MP_OKAY;
   }
   return ret;
}
#endif /* WIN32 */

#if !defined(MP_WIN_CSP) && defined(__linux__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 25)
#define MP_GETRANDOM
#include <sys/random.h>
#include <errno.h>

static int s_read_getrandom(mp_digit *p)
{
   int ret;
   do {
      ret = getrandom(p, sizeof(*p), 0);
   } while ((ret == -1) && (errno == EINTR));
   if (ret == sizeof(*p)) return MP_OKAY;
   return -1;
}
#endif
#endif

/* We assume all platforms besides windows provide "/dev/urandom".
 * In case yours doesn't, define MP_NO_DEV_URANDOM at compile-time.
 */
#if !defined(MP_WIN_CSP) && !defined(MP_NO_DEV_URANDOM)
#ifndef MP_DEV_URANDOM
#define MP_DEV_URANDOM "/dev/urandom"
#endif
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

static int s_read_dev_urandom(mp_digit *p)
{
   ssize_t r;
   int fd;
   do {
      fd = open(MP_DEV_URANDOM, O_RDONLY);
   } while ((fd == -1) && (errno == EINTR));
   if (fd == -1) return -1;
   do {
      r = read(fd, p, sizeof(*p));
   } while ((r == -1) && (errno == EINTR));
   close(fd);
   if (r != sizeof(*p)) return -1;
   return MP_OKAY;
}
#endif

#if defined(MP_PRNG_ENABLE_LTM_RNG)
unsigned long (*ltm_rng)(unsigned char *out, unsigned long outlen, void (*callback)(void));
void (*ltm_rng_callback)(void);

static int s_read_ltm_rng(mp_digit *p)
{
   unsigned long ret;
   if (ltm_rng == NULL) return -1;
   ret = ltm_rng((void *)p, sizeof(*p), ltm_rng_callback);
   if (ret != sizeof(*p)) return -1;
   return MP_OKAY;
}
#endif

static int s_rand_digit(mp_digit *p)
{
   int ret = -1;

#if defined(MP_ARC4RANDOM)
   ret = s_read_arc4random(p);
   if (ret == MP_OKAY) return ret;
#endif

#if defined(MP_WIN_CSP)
   ret = s_read_win_csp(p);
   if (ret == MP_OKAY) return ret;
#else

#if defined(MP_GETRANDOM)
   ret = s_read_getrandom(p);
   if (ret == MP_OKAY) return ret;
#endif
#if defined(MP_DEV_URANDOM)
   ret = s_read_dev_urandom(p);
   if (ret == MP_OKAY) return ret;
#endif

#endif /* MP_WIN_CSP */

#if defined(MP_PRNG_ENABLE_LTM_RNG)
   ret = s_read_ltm_rng(p);
   if (ret == MP_OKAY) return ret;
#endif

   return ret;
}

/* makes a pseudo-random int of a given size */
static int s_gen_random(mp_digit *r)
{
   int ret = s_rand_digit(r);
   *r &= MP_MASK;
   return ret;
}

int mp_rand(mp_int *a, int digits)
{
   int     res;
   mp_digit d;

   mp_zero(a);
   if (digits <= 0) {
      return MP_OKAY;
   }

   /* first place a random non-zero digit */
   do {
      if (s_gen_random(&d) != MP_OKAY) {
         return MP_VAL;
      }
   } while (d == 0u);

   if ((res = mp_add_d(a, d, a)) != MP_OKAY) {
      return res;
   }

   while (--digits > 0) {
      if ((res = mp_lshd(a, 1)) != MP_OKAY) {
         return res;
      }

      if (s_gen_random(&d) != MP_OKAY) {
         return MP_VAL;
      }
      if ((res = mp_add_d(a, d, a)) != MP_OKAY) {
         return res;
      }
   }

   return MP_OKAY;
}
#endif

/* ref:         HEAD -> develop */
/* git commit:  8b9f98baa16b21e1612ac6746273febb74150a6f */
/* commit time: 2018-09-23 21:37:58 +0200 */
