See the comments of the `check_flag` function for how the flag checking works.
The function also decrypts and reencrypts itself with a xorshift16 PRNG.

Approaches:

- Static
    - write a binja/ghidra module
    - write your own disassembler, or use a preexisting one
- Dynamic
    - [uxn32](https://github.com/randrew/uxn32) is probably the easiest way to debug, though you'll need to patch the rom to add debugger breakpoints (see the `DBG` macro in [auxin.tal](auxin.tal))
    - i guess you can also patch the official uxn emulator?

To build: `uxnasm auxin.tal auxin.rom && python3 encrypt.py`
