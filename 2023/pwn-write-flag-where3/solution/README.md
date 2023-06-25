# Google CTF 2023 - pwn: write-flag-where3 writeup

In part 3, we have an additional check forbidding writing to the chal binary memory space. We can still overwrite stack or libc etc. but our previous code won’t work this time.

We can create a jump instruction using '}' - it’s a two-byte instruction “jnp <byte>”. We can make the second byte an unknown flag byte and prepare first an array of invalid instructions, and a nopsled afterwards. By modifying length of these two parts and checking whether we crash or not, we can brute force the flag character by character.
