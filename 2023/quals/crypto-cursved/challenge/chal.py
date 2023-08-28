# Copyright 2023 Google LLC
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

from hashlib import sha256
from os import urandom

def bytes_to_hexstr(buf):
  return "".join(["{0:02X}".format(b) for b in buf])
def bytes_to_int(buf):
  return int(bytes_to_hexstr(buf), 16)
def random_int(n):
  return bytes_to_int(urandom(n))
def sha256_as_int(x):
  return int(sha256(x).hexdigest(), 16)
def check_type(x, types):
  if len(x) != len(types):
    return False
  for a,b in zip(x, types):
    if not isinstance(a, b):
      return False
  return True

class Curve:
  def __init__(self, p, D, n):
    self.p = p
    self.D = D
    self.n = n
  def __repr__(self):
    return f"Curve(0x{self.p:X}, 0x{self.D:X})"
  def __eq__(self, other):
    return self.p == other.p and self.D == other.D
  def __matmul__(self, other):
    assert(check_type(other, (int, int)))
    assert(other[0]**2 % self.p == (self.D*other[1]**2 + 1) % self.p)
    return Point(self, *other)

class Point:
  def __init__(self, C, x, y):
    assert(isinstance(C, Curve))
    self.C = C
    self.x = x
    self.y = y
  def __repr__(self):
    return f"(0x{self.x:X}, 0x{self.y:X})"
  def __eq__(self, other):
    assert(self.C == other.C)
    return self.x == other.x and self.y == other.y
  def __add__(self, other):
    assert(self.C == other.C)
    x0, y0 = self.x, self.y
    x1, y1 = other.x, other.y
    return Point(self.C, (x0*x1 + self.C.D*y0*y1) % self.C.p, (x0*y1 + x1*y0) % self.C.p)
  def __rmul__(self, n):
    assert(check_type((n,), (int,)))
    P = self.C @ (1, 0)
    Q = self
    while n:
      if n & 1:
        P = P + Q
      Q = Q + Q
      n >>= 1
    return P
  def to_bytes(self):
    l = len(hex(self.C.p)[2:])
    return self.x.to_bytes(l, "big") + self.y.to_bytes(l, "big")

class Pub:
  def __init__(self, G, P):
    self.G = G
    self.P = P
  def verify(self, m, sig):
    assert(check_type(sig, (Point, int)))
    (R, s) = sig
    e = sha256_as_int(R.to_bytes() + self.P.to_bytes() + m) % self.G.C.n
    return s*self.G == R + e*self.P

class Priv:
  def __init__(self, k, G):
    self.k = k
    self.G = G
    self.P = k*G
  def get_pub(self):
    return Pub(self.G, self.P)
  def sign(self, m):
    r = random_int(16) % self.G.C.n
    R = r*self.G
    e = sha256_as_int(R.to_bytes() + self.P.to_bytes() + m) % self.G.C.n
    return (R, (r + self.k*e) % self.G.C.n)

class Problem:
  def __init__(self, pub):
    self.pub = pub
    self.nonce = None
  def gen(self):
    self.nonce = urandom(16)
    return self.nonce
  def parse_response(self, resp):
    try:
      Rx, Ry, s = (int(t) for t in resp.split())
      return (self.pub.P.C @ (Rx, Ry), s)
    except:
      pass
    return None
  def test(self, sig):
    if self.nonce is None:
      return False
    return self.pub.verify(self.nonce, sig)

from config import FLAG, PRIVATE_KEY

def main():
  C = Curve(0x34096DC6CE88B7D7CB09DE1FEC1EDF9B448D4BE9E341A9F6DC696EF4E4E213B3,
            0x3,
            0x34096DC6CE88B7D7CB09DE1FEC1EDF9B448D4BE9E341A9F6DC696EF4E4E213B2)
  G = C @ (0x2, 0x1)
  priv = Priv(PRIVATE_KEY, G)
  pub = priv.get_pub()
  print(f"pub = {pub.P}")

  prob = Problem(pub)
  nonce = prob.gen()
  print(f"nonce = {bytes_to_hexstr(nonce)}")

  resp = input("sig = ")
  sig = prob.parse_response(resp)
  if sig is not None and prob.test(sig):
    print(FLAG)
  else:
    print("Please try again!")

if __name__ == "__main__":
  try:
    main()
  except:
    pass
