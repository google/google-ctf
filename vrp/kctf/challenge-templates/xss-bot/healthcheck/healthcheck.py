#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
from pwn import *

r = remote('127.0.0.1', 1337)
l = listen()

r.readuntil(b'URL to open.', timeout=10)
r.send(bytes('http://localhost:{}/ok'.format(l.lport), 'ascii'))

_ = l.wait_for_connection()
l.readuntil(b'GET /ok HTTP/1.1')

exit (0)
