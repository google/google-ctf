#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
from pwn import *

r = remote('127.0.0.1', 1337)
l = listen()

r.readuntil('URL to open.', timeout=10)
r.send('http://localhost:{}/ok'.format(l.lport))

_ = l.wait_for_connection()
l.readuntil('GET /ok HTTP/1.1')

exit (0)
