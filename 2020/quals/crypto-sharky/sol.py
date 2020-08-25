#! /usr/bin/python3
#Copyright 2020 Google LLC
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import binascii
import struct
from typing import List, Sequence
import sha256

# type hints
State = Sequence[int]


class ExtendedState:

  def __init__(self,
               a=None,
               b=None,
               c=None,
               d=None,
               e=None,
               f=None,
               g=None,
               h=None,
               tmp1=None,
               tmp2=None,
               tmp3=None,
               sigma0=None,
               sigma1=None,
               maj=None,
               ch=None,
               w=None,
               k=None):
    self.a = a
    self.b = b
    self.c = c
    self.d = d
    self.e = e
    self.f = f
    self.g = g
    self.h = h
    self.tmp1 = tmp1
    self.tmp2 = tmp2
    self.tmp3 = tmp3
    self.sigma0 = sigma0
    self.sigma1 = sigma1
    self.maj = maj
    self.ch = ch
    self.w = w
    self.k = k

  def unknowns(self):
    res = 0
    for x in (self.a, self.b, self.c, self.d, self.e, self.f, self.g, self.h,
              self.tmp1, self.tmp2, self.tmp3, self.sigma0, self.sigma1,
              self.maj, self.ch, self.w, self.k):
      if x is None:
        res += 1
    return res

  def ck(self, res, deps):
    return res is None and all(x is not None for x in deps)

  def solve_state(self):
    """Tries to solve for not yet known variables in a given state."""
    sha = sha256.SHA256()
    if self.ch is None and None not in (self.e, self.f, self.g):
      self.ch = (self.e & self.f) ^ (~self.e & self.g)
    if self.maj is None and None not in (self.a, self.b, self.c):
      self.maj = (self.a & self.b) ^ (self.a & self.c) ^ (self.b & self.c)
    if self.sigma0 is None and self.a is not None:
      self.sigma0 = (
          sha.rotate_right(self.a, 2) ^ sha.rotate_right(self.a, 13)
          ^ sha.rotate_right(self.a, 22))
    if self.sigma1 is None and self.e is not None:
      self.sigma1 = (
          sha.rotate_right(self.e, 6) ^ sha.rotate_right(self.e, 11)
          ^ sha.rotate_right(self.e, 25))
    cnt = 0
    for x in (self.tmp1, self.h, self.sigma1, self.ch, self.k, self.w):
      if x is None:
        cnt += 1
    if cnt == 1:
      if self.tmp1 is None:
        self.tmp1 = (self.h + self.sigma1 + self.ch + self.k +
                     self.w) & 0xffffffff
      else:
        diff = self.tmp1
        for x in (self.h, self.sigma1, self.ch, self.k, self.w):
          if x is not None:
            diff -= x
        diff &= 0xffffffff
        if self.h is None:
          self.h = diff
        if self.sigma1 is None:
          self.sigma1 = diff
        if self.ch is None:
          self.ch = diff
        if self.k is None:
          self.k = diff
        if self.w is None:
          self.w = diff
    cnt = 0
    for x in (self.tmp2, self.tmp1, self.sigma0, self.maj):
      if x is None:
        cnt += 1
    if cnt == 1:
      if self.tmp2 is None:
        self.tmp2 = (self.tmp1 + self.sigma0 + self.maj) & 0xffffffff
      else:
        diff = self.tmp2
        for x in (self.tmp1, self.sigma0, self.maj):
          if x is not None:
            diff -= x
        diff &= 0xffffffff
        if self.tmp1 is None:
          self.tmp1 = diff
        if self.sigma0 is None:
          self.sigma0 = diff
        if self.maj is None:
          self.maj = diff
    cnt = 0
    for x in (self.tmp3, self.tmp1, self.d):
      if x is None:
        cnt += 1
    if cnt == 1:
      if self.tmp3 is None:
        self.tmp3 = (self.d + self.tmp1) & 0xffffffff
      elif self.tmp1 is None:
        self.tmp1 = (self.tmp3 - self.d) & 0xffffffff
      else:
        self.d = (self.tmp3 - self.tmp1) & 0xffffffff

  def solve_before(self, before) -> bool:
    """Tries to find some variables in a state given the previous state."""

    def alt(x, y):
      if x is not None:
        return x
      return y

    self.a = alt(self.a, before.tmp2)
    self.b = alt(self.b, before.a)
    self.c = alt(self.c, before.b)
    self.d = alt(self.d, before.c)
    self.e = alt(self.e, before.tmp3)
    self.f = alt(self.f, before.e)
    self.g = alt(self.g, before.f)
    self.h = alt(self.h, before.g)

  def solve_after(self, after) -> bool:
    """Tries to find some variables in a state given the next state."""

    def alt(x, y):
      if x is not None:
        return x
      return y

    self.tmp2 = alt(self.tmp2, after.a)
    self.a = alt(self.a, after.b)
    self.b = alt(self.b, after.c)
    self.c = alt(self.c, after.d)
    self.tmp3 = alt(self.tmp3, after.e)
    self.e = alt(self.e, after.f)
    self.f = alt(self.f, after.g)
    self.g = alt(self.g, after.h)

  def __repr__(self):
    s = [
        self.a, self.b, self.c, self.d, self.e, self.f, self.g, self.h,
        self.tmp1, self.tmp2, self.tmp3, self.sigma0, self.sigma1, self.maj,
        self.ch, self.k, self.w
    ]
    s = tuple('%08x' % x if isinstance(x, int) else str(x) for x in s)
    return ('a=%s, b=%s, c=%s, d=%s, e=%s, f=%s, g=%s, h=%s,\n'
            'tmp1=%s, tmp2=%s, tmp3=%s, s0=%s, s1=%s, maj=%s, ch=%s,\n'
            'k=%s, w=%s' % s)


def solve_all(states: List[State]):
  """Tries to find as many unknown variables given a list of states."""
  unknowns = sum(s.unknowns() for s in states)
  n = len(states)
  while True:
    for i in range(n - 1):
      states[i].solve_state()
      states[i + 1].solve_before(states[i])
    for i in range(n - 2, -1, -1):
      states[i + 1].solve_state()
      states[i].solve_after(states[i + 1])
    cnt = sum(s.unknowns() for s in states)
    if cnt == unknowns:
      return
    unknowns = cnt


def get_states(msg: bytes, digest: bytes, round_keys=None):
  sha = sha256.SHA256()
  states = [ExtendedState() for i in range(65)]
  m_padded = sha.padding(msg)
  if len(m_padded) != 64:
    raise ValueError('not implemented')
  w = sha.compute_w(m_padded)
  last = struct.unpack('>8L', digest)
  d = [(x - y) & 0xffffffff for x, y in zip(last, sha.h)]
  s = states[-1]
  s.a, s.b, s.c, s.d, s.e, s.f, s.g, s.h = d
  s = states[0]
  s.a, s.b, s.c, s.d, s.e, s.f, s.g, s.h = sha.h
  for i, wi in enumerate(w):
    states[i].w = wi
  for i, k in enumerate(round_keys):
    states[i].k = k
  return states


def debug_sha256(msg: bytes, digest: bytes, rk: List[int], verbose=False):
  states = get_states(msg, digest, rk)
  solve_all(states)
  out = []
  if verbose:
    for i, s in enumerate(states):
      print(i, repr(s))
  for i, v in enumerate(rk):
    if v is None:
      if isinstance(states[i].k, int):
        out.append(hex(states[i].k))
        print(i, hex(states[i].k))
      else:
        print(i, states[i].k)
  print('KEYS:')
  print(','.join(out))


if __name__ == '__main__':
  MSG = b'Encoded with random keys'
  sha = sha256.SHA256()
  rk = sha.k[:]
  for i in range(8):
    rk[i] = None

  faulty_sha = binascii.unhexlify(input('Message Digest: ').encode())
  debug_sha256(MSG, faulty_sha, rk)
