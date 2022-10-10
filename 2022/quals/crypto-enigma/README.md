# Enigma
Cryptanalysis has advanced a long way.

Can you break Enigma *without* a known plaintext?

## About this machine

The Enigma was a collection of cryptographic ciphering machines used by Germany
and its allies prior to and during WWII.

This directory contains C++ code that emulates one particular Enigma machine: a
1939 M3 Enigma machine, with 3 rotor slots, rotor choices I - VIII (including
the 3 Naval rotors), reflector B, and 10 plugboard pairs.

## Message Format

All encrypted messages in this challenge are written in German.

### Non-ASCII Letters
The Enigma only supports the 26 ASCII capital letters - it does not support
ß, umlauts, punctuation, or spaces.

To get around this, German operators would encode messages using substitutes.


#### Letters
 - Everything is capitalized.
 - Umlaut vowels are replaced by their non-umlaut form, followed by an E.
   For example, the letter `Ä` is written `AE`.
 - The letter `ß` is written `SS`.

#### Punctuation
 - `.` is written `X`.
 - `,` is written `Y`.
 - `-`, `—`, `/`, and `\` are all written `YY`.
 - `?` is written `UD`.
 - `:` is written `XX`.
 - Quotes (`'`, `"`) are written `J`. So, `"FOO"` is written `JFOOJ`. This can
   also be used to stress text.
 - Parentheses and other forms of brackets are written `KK`. So, `(FOO)` is
   written `KKFOOKK`.
 - Spaces are completely skipped.

This encoding is obviously lossy, making deciphering messages rather annoying.

### Message Key

In wartime use, Germany and its allies used both a fixed daily key and a
per-message key. The first few characters of a message were encoded using the
fixed daily key and specified the rotor positions that would be used for the
rest of the message. Only the rotor positions were changed per-message; all
other settings were too difficult to adjust and therefore only changed daily.

Due to a lack of available information on the encoding of the message key at the
start of each message, and the fact that it is irrelevant to the cryptanalysis
of a single message, separate message keys are *not* included in this challenge.
All messages include only the message itself encrypted with the specified key.

## Fernet files
We understand that trying to parse `ICHS AGEH IERM ITJE INZI TATJ X` into
`ICH SAGE HIERMIT "EIN ZITAT".` is a task that depends greatly on whether your
team has a member who speaks German. Without one, it would be difficult even after your
team has broken the Enigma. Our goal with this challenge is not to test your
command of German - Bletchley Park would have simply employed German speakers
for that purpose. Therefore, we have provided the original messages encrypted
with the modern Fernet cipher as well, which supports all the detailed
punctuation we could need. The key is the rotor/ring/plugboard settings in the
exact same format as used by `machine.cc`.

Example:

```
./encrypt_modern.py decrypt $(cat messages/may_09_2022/settings) < messages/may_09_2022/comet.fernet.txt > may_09_original
```

The file `may_09_original` will be byte-for-byte identical with
`messages/may_09_2022/comet.original.txt`.

## Directory Layout

### `enigma`

This directory contains the code for the machine itself. Makefile and Bazel
BUILD rules are provided. `enigma.h` provides a library implementation;
`machine.cc` provides a command-line interface.

### `encode.py`

This is a simple utility script for cleaning up text and formatting with only
the 26 ASCII capital letters.

### `messages`

For testing, we provide a number of previously-decrypted sample messages (in
`messages/may_[0-9]{2}_2022`. Files are as follows:

 - `.original.txt`: The original message to be encrypted.
 - `.plaintext.txt`: The same message, formatted for Enigma (via `encode.py`).
 - `.ciphertext.txt`: The ciphertext after being encrypted via the Enigma
   machine.
 - `settings`: The settings used for that ciphertext.
 - `.fernet.txt`: The original message, encoded with the Fernet cipher (via
   `encrypt_modern.py`).

In wartime, there would often be multiple messages that discussed the same
topic, and breaking any message would leak sensitive information. That pattern
happens here: there are two messages with the flag. (`messages/may_12_2022` and
`messages/may_14_2022`). They are *not* the same message, but they both describe
the flag. You only need to break one of them.

### `encrypt_modern.py`

Encrypts or decrypts a message using Fernet. The key is passed as a series of
space-separated command-line arguments. Usage is:

```
./encrypt_modern.py [encrypt|decrypt] {key pieces} < input > output
```

## Constraints
While an Enigma machine could accept multiple copies of the same rotor, each
machine was only shipped with one copy of each. Therefore, no key includes a
duplicated rotor.

Germany generated its codebooks by rolling dice. However, it enforced reules
meant to ensure there was "enough variation" between days. If those rules
were violated, dice would be rerolled. Those rules are:
 - Every day must include at least one "naval rotor" (rotors VI-VIII).
 - The same naval rotor cannot be used in the same position on two consecutive
   days.

These constraints apply in this challenge. While certain other randomness
constraints were applied in some divisions during certain time periods, only the
restrictions mentioned here or enforced by `machine.cc` apply to this challenge.
Keys are otherwise random.


