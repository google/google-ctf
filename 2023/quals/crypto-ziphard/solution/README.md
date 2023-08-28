# GCTF'23 - ZIP (hard variant) (Crypto)

## Challenge Description

Someone rolled their own implementation of PKZIP-compatible encryption
to produce an encrypted ZIP file. The PKZIP-compatible cipher is old
and known to be weak, but did the author leak sufficient information
for you to decrypt the flag?

## Introduction

The challenge provides two files--a password-protected ZIP file, named
`hard.zip` as well as a Python script that was presumably used to
generate it, named `hard.py`.

A review of Biham and Kocher's [A Known Plaintext Attack on the PKZIP
Stream
Cipher](https://link.springer.com/content/pdf/10.1007/3-540-60590-8_12.pdf)
could be quite helpful before attempting this challenge.

## Solution

Reviewing `hard.py` shows that is a pure Python implementation of a
quite minimal ZIP archiver. The script takes three command line
arguments: a password for PKZIP encryption, a file containing the
flag, and an encrypted ZIP file to create. The script ensures that the
flag begins with `CTF{` and ends with `}`. Comparing the encryption
algorithm to the [PKWARE
specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
the implementation appears correct. In addition to encrypting
`flag.txt` and placing it in the archive, the script also generates
four random bytes as `junk.dat` and encrypts that file and places it
in the archive as well.

A review of the specification also states that PKWARE encryption
incorporates a 12-byte encrypted nonce, and by convention, the last
byte of the nonce is the most significant byte of the CRC32 value of
the plaintext. `hard.py` follows this convention.

Additional review of `hard.py` shows that it encodes strings using a
character set of `utf-8-sig`. What is `utf-8-sig`? This means to
encode using UTF-8 and to prepend with a quite-unnecessary Unicode
byte order marker. In UTF-8 that byte order marker is encoded as `ef
bb bf`. Depending on settings in the Save As dialog, it is possible to
accidentally generate a file in this format using Windows Notepad, and
the invisible BOM can become quite frustrating when passing the
resulting file to other tools. But here, the insertion of `ef bb bf`
into `flag.txt` just provides three extra bytes of known plaintext.

Nothing is wrong with the random number generation, including for
`junk.dat`, so some brute forcing of the CRC value is in order to
determine the plaintext of `junk.dat`. Even on a single core this can
be done in a minute or two.

Given the CRC byte incorporated in the nonce and the BOM inserted into
`flag.txt`, now we know nine plaintext bytes for `flag.txt` (eight of
which are contiguous) and given the CRC byte and brute-forced
plaintext bytes, we have five plaintext bytes for `junk.dat` (all five
of which are contiguous).

Next, we need to find or implement the attack of Biham and
Kocher. `bkcrack` is an [excellent
tool](https://github.com/kimci86/bkcrack) and in reviewing the
documentation, it takes a minimum of eight contiguous bytes of known
plaintext to generate possible keys, and an additional four bytes of
known plaintext to eliminate incorrect keys and narrow down to the
correct keys. Do we have this? Yes, but only split across two files
that happened to be encrypted using the same password. Out of the box,
`bkcrack` does not account for this possibility, so a quick patch is
in order to add some code to generate keys based on known plaintext
from `flag.txt`, but then filter out those that do not correctly
decrypt `junk.dat`. A very quick patch is given in
`bkcrack-1.5.0.patch`; it removes the check for 12 plaintext bytes,
and expects files in the current directory for `second_plaintext`
(with the five byte plaintext recovered for `junk.dat`) and
`second_ciphertext` (with 16 bytes consisting of the 12-byte encrypted
nonce including the CRC byte, and four-byte encrypted plaintext). The
patched `bkcrack` then uses each candidate key to decrypt
`second_ciphertext` and compares the result to `second_plaintext`; all
keys except the one that correctly decrypts the plaintext are filtered
out.

The full, automated solution is given in `hard.sh`. The script first
recovers the known plaintext bytes for `flag.txt` and for passing to
`bkcrack` using the `-x` command line option. The script then copies
the 16-byte ciphertext for `junk.dat` to the file `second_ciphertext`,
and calls `crackcrc` to guess the four-byte plaintext, and after
prepending the plaintext with the most significant byte of the CRC,
`crackcrc` saves it to the file `second_plaintext`.

You may download `bkcrack`
[1.5.0](https://github.com/kimci86/bkcrack/releases) and patch it
using:

```
tar zxf bkcrack-v1.5.0.tar.gz
cd bkcrack-1.5.0
patch -p1 < /path/to/bkcrack-1.5.0.patch
```

Next, the patched `bkcrack` executes; using eight cores `bkcrack`
discovers the key in about one hour and fifteen minutes:

```
16+0 records in
16+0 records out
16 bytes copied, 0.00018558 s, 86.2 kB/s
wanted crc = 3b3953bc
start value = 0
stop value = ffffffff
plaintext found: e2f2ba77
bkcrack 1.5.0 - 2023-06-23
[09:45:30] Attack on 4194304 Z values at index 6
Keys: 7796d1ea 96defd9f d7043705
91.9 % (3854234 / 4194304)
[10:59:39] Keys
7796d1ea 96defd9f d7043705
```

Given the keys, the `--change-keys` `bkcrack` option can be used to
re-encrypt the ZIP file using a different password, and then the file
can be decrypted to recover and submit the flag value from `flag.txt`
(BOM removed, of course).