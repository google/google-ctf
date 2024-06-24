# How to change the flag

The flag **must** be a multiple of 8 characters, this is because of a restriction of TEA. Ideally should be 32 characters long, because the TEA encryption is hardcoded for this length.

Generate the new encrypted flag with `challenge/helpers/tea_encrypt.c`, then plug in the result in `challenge/src/z80/encrypted_flag.asm`. Make sure to change it in `metadata.yaml`.