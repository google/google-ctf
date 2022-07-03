#!/usr/bin/env python3

LENGTH = int(2.6 * 1024)

with open('test.in', 'wb') as fout:
    data = bytes(x & 0xFF for x in range(LENGTH))
    fout.write(data)
