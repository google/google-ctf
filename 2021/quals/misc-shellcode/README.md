# ABC ARM AND AMD

The goal of this challenge is to have the players write short (280 bytes max)
alphanumeric shell code that is valid on both aarch64 and x86-64. The shell code
must print the contents of a 'flag' file.

The players are given the host applications and their corresponding libc files
for the two architectures.

The service component of this challenge is a python script that accepts a
payload from the player and performs content validation and then validates the
payload by executing it under each architecture. The aarch64 binary is emulated
with qemu.

The 'flag' file that the payload reads is randomly generated per-attempt. This
is to prevent players from cat'ing back the contents of the file and solving the
challenge in a piecewise manner. This is likely unnecessary since the nsjail is
configured without networking.

A possible solution is provided in `./solution/sol.py`
