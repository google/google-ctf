# Weather (Hardware) - Solution
## Spoiler ahead - you have been warned

### Getting access to firmware flash

The first step is to bypass the I2C address filtering. The filtering relies on
the input being compared - as string - to a list of allowed/disallowed 7-bit
ports. There are two issues here that need to be combine for the bypass:

  * The string comparison code stops comparison when it reaches the end of the
known-good string (i.e. it basically does a prefix check only).
  * The string-to-int conversion doesn't check for an integer overflow.

For example, if we want to get access to port `55`, and the list of allowed
ports has one entry - `"123"` - then it's enough to send a port number starting
with `123` that is equal to `55 mod 256`. This could be e.g. `12343`, `123191`,
and so on.

Bypassing the I2C address filtering allows us to get access to the I2C port of
the flash which stores the currently executed firmware.

This on the other hand allows us to do two things:

  * Dump the flash.
  * Write 0 bits in selected places.

### Executing the code and reading the flag

After dumping the flash we must find some place to store our payload (end of
firmware is ideal, since there is a lot of `FF` bytes there), and figure out 
how to redirect execution to our code.

The simplest method to do this is to just clear all the bits from some location
to the shellcode, as byte `00` is a `NOP` on 8052. The healthcheck however is
doing this differently - basically there is a hardcoded location (one of many)
which can be reprogrammed to a LJMP SHELLCODE (by just clearing bits).

The rest of the task is basically shellcoding, i.e. writing code that uses the
MMIO registers to access the flag EEPROM, reads the flag, and sends it to the
player using the serial connection (another MMIO).