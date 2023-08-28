# Solution

You need to reverse engineer the given binary. It encodes PPM
picture files to a custom PNG extension image.
Reversing shows it reorders the pixels using a custom interlace method
based on the Hilbert curve; and uses several custom filter types,
based on xor and slightly further lookbehind than usual PNG filters.

Players need to write a decoder for the file format - they can use
the provided binary as a blackbox encoder to get more test files.

The flag is written as colored characters on the decoded picture. It
spells:
```
CTF{0cc4sion4lly_PNG2_is_actuAlly_5m4ll3r}
```

You can run the solver by `make solve`.
