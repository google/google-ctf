# Compression format

(Note to self: the flag is stored in /flag)

1. Header
- u32 MAGIC "TINY"

2. Blocks
- u8 literal
- if literal == 0xff:
  - it's not a literal;
  - varint offset
  - varint length
  - if offset == 0, then special case:
    - if length == 0, EOF
    - if length == 1, literal 0xff
