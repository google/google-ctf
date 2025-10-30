### webz

So you are pretty good at browser pwn. 
Let's try something new.
Maybe [The WebP 0day](https://blog.isosceles.com/the-webp-0day) inspired you too?

### Exploitation

google-zlib removes the [oversubscribed & incomplete](https://github.com/madler/zlib/blob/develop/inftrees.c#L125-L133) tree checks from zlib (similar to the bug that led to the webp [0day from 2023](https://blog.isosceles.com/the-webp-0day/)). 

```diff
From 2c282408771115b3cf80eeb9572927b796ddea79 Mon Sep 17 00:00:00 2001
From: Brendon Tiszka <tiszka@google.com>
Date: Wed, 21 May 2025 15:11:52 +0000
Subject: [PATCH] [google-zlib] Increase Huffman Table Size

The basic idea is to use a bigger root & secondary table for both
dists and lens, allowing us to avoid oversubscription chekcs.
---
 inftrees.c | 18 ------------------
 inftrees.h | 18 +++++-------------
 2 files changed, 5 insertions(+), 31 deletions(-)

diff --git a/inftrees.c b/inftrees.c
index a127e6b..7a8dd2e 100644
--- a/inftrees.c
+++ b/inftrees.c
@@ -122,16 +122,6 @@ int ZLIB_INTERNAL inflate_table(codetype type, unsigned short FAR *lens,
         if (count[min] != 0) break;
     if (root < min) root = min;
 
-    /* check for an over-subscribed or incomplete set of lengths */
-    left = 1;
-    for (len = 1; len <= MAXBITS; len++) {
-        left <<= 1;
-        left -= count[len];
-        if (left < 0) return -1;        /* over-subscribed */
-    }
-    if (left > 0 && (type == CODES || max != 1))
-        return -1;                      /* incomplete set */
-
     /* generate offsets into symbol table for each length for sorting */
     offs[1] = 0;
     for (len = 1; len < MAXBITS; len++)
@@ -200,11 +190,6 @@ int ZLIB_INTERNAL inflate_table(codetype type, unsigned short FAR *lens,
     used = 1U << root;          /* use root table entries */
     mask = used - 1;            /* mask for comparing low */
 
-    /* check available table space */
-    if ((type == LENS && used > ENOUGH_LENS) ||
-        (type == DISTS && used > ENOUGH_DISTS))
-        return 1;
-
     /* process all codes and make table entries */
     for (;;) {
         /* create table entry */
@@ -270,9 +255,6 @@ int ZLIB_INTERNAL inflate_table(codetype type, unsigned short FAR *lens,
 
             /* check for enough space */
             used += 1U << curr;
-            if ((type == LENS && used > ENOUGH_LENS) ||
-                (type == DISTS && used > ENOUGH_DISTS))
-                return 1;
 
             /* point entry in root table to sub-table */
             low = huff & mask;
diff --git a/inftrees.h b/inftrees.h
index 396f74b..42c2c44 100644
--- a/inftrees.h
+++ b/inftrees.h
@@ -35,19 +35,11 @@ typedef struct {
     01000000 - invalid code
  */
 
-/* Maximum size of the dynamic table.  The maximum number of code structures is
-   1444, which is the sum of 852 for literal/length codes and 592 for distance
-   codes.  These values were found by exhaustive searches using the program
-   examples/enough.c found in the zlib distribution.  The arguments to that
-   program are the number of symbols, the initial root table size, and the
-   maximum bit length of a code.  "enough 286 9 15" for literal/length codes
-   returns 852, and "enough 30 6 15" for distance codes returns 592. The
-   initial root table size (9 or 6) is found in the fifth argument of the
-   inflate_table() calls in inflate.c and infback.c.  If the root table size is
-   changed, then these maximum sizes would be need to be recalculated and
-   updated. */
-#define ENOUGH_LENS 852
-#define ENOUGH_DISTS 592
+/* Memory/speed tradeoff. Alocate more-than-ENOUGH space for LENS and
+   DISTS so we can remove overflow checks from `inflate`.
+*/
+#define ENOUGH_LENS (1 << 15)
+#define ENOUGH_DISTS (1 << 15)
 #define ENOUGH (ENOUGH_LENS+ENOUGH_DISTS)
 
 /* Type of code to build for inflate_table() */
-- 
2.50.0.rc0.642.g800a2b2222-goog
```

google-zlib also allocates a large enough buffer to account for oversubscribed & incomplete trees – 210 entries – so that oversubscribed & incomplete tree combinations cannot result in OOB writes in the huffman table itself, like the webp 0day from 2023 did.

However, there are other methods for exploiting incorrect oversubscribed & incomplete tree checks. In zlib specifically, incomplete trees can leave the huffman table slots uninitialized, which can result in a type confusion between LEN and DIST codes, which then can be used to break the inffast invariant and trigger linear buffer overflow.

From there, exploitation is easy, overflow z_stream object -> relative infoleak -> arb read -> overwrite `zalloc` function pointer -> ret2libc.
