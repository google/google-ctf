# Eldar

## Basics

In this challenge the players need put the correct flag in a `serial.c` file, compile it as a shared library (`libserial.so`) and execute the binary (`eldar`) provided by us.

The code in the binary is very simple, it just checks the `fail` variable (which is zero by default) and based on that it either shows an "incorrect serial" error or tells you that the `serial` was correct.

The trick is that the `fail` variable is calculated by using ELF relocations based on the idea of [this paper](https://www.cs.dartmouth.edu/~sergey/wm/woot13-shapiro.pdf).

## What does the challenge do?

The challenge do the following:
* a modified RC4 PRNG implemented in this "weird LD loader machine" uses the first part of the flag/serial as key bytes and calculates 3 byte checksums for every 2 bytes of the flag bytes
* these checksum bytes are checked using linear system of equations and this check is also implemented in this weird machine
* for the second part of the flag, there is no RC4 magic, but the relocation entries inject x86_64 bytecode into the binary and some calculations (`add`, `sub`, `xor`, `shl`, `ror`, etc) are done on the flag bytes before the equation checks

### Operations of our weird machine

Our weird machine supports the following operations:
* overwriting bytes with constant values (`*addr = const`)
* copying bytes from one address to another (`memcpy`)
* sum two values (`*addr = *value1_addr + *value2_addr`)

### Consideration against unintended solutions

* program execution length should be constant, intruction counting should not work
* after each stages temporary used memory is wiped
* RC4 is modified a bit, so it is hard to guess how it is calculated by just looking at the output bytes
* only one bit is leaked (`fail=0` or `1`) whether the flag is correct or not (blindly bruteforcing the flag while observing the full checksum is harder)

### Consideration against fake flags

* flag bytes are checked to be within 33..126 range (`charset_check.c`)
* RC4 converts 2 bytes of the flag into 3 bytes in an unambiguous way (there are no conflicts while reversing the process - at least in case of the correct flag)
* equation checks only accept allow positive values, so all equation results should be equal to zero to pass the check (this is not allowed: `eq1=-3, eq2=3` -> `sum=0`)

## Trivia

The name of the challenge ("`Eldar`") is a reference to `elves` which is a reference for the `ELF` file format.

The challenge is similar to GitS 2012's `Khazad` challenge in that sense that that challenge did similar ELF magic but used the `DWARF` section of the ELF binary.