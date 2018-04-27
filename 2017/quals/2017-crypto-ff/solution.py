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

# Uses Python 3.x
from os import urandom
from time import time
     
def extended_gcd(a, b):
  """ return (g,v) such that 
      g = gcd(a,b) and
      g == v*a (mod b)"""
  r, s = a, b
  u, v = 1, 0
  while r:
    q = s // r
    r, s = s - q * r, r
    u, v = v - q * u, u
  if s < 0:
    s, v = -s, -v
  return (s, v % b)

def modinv(a,p):
  s, v = extended_gcd(a, p)
  if s != 1:
    raise ValueError("a does not have an inverse")
  return v

def bitcount(n):
  res = 0
  while n:
    res += n%2
    n//=2
  return res

def randint(size):
    r = urandom((size+7)//8)
    q = 0
    for c in r: q = 256*q + c
    return q % (2**size)
  
def genq(size):
  while True:
    q = randint(size) | (1 << (size-1)) | 1
    if bitcount(q)+4 > size//2:
      continue
    if pow(2,q,q)==2:
      return q

def genqb(size, bc):
  while True:
    q = randint(size) | (1 << (size-1)) | 1
    while bitcount(q) < bc:
      q |= 1 << (randint(8) % size)
    if bitcount(q) == bc and pow(3,q,q)==3:
      return q

def genp(q, size):
  while True:
    p = randint(size) | (1 << (size-1))
    p = p//q * q + 1
    if pow(2,p,p) == 2:
      return p

p = 32163437489387646882545837937802838313337646833974044466731567532754579958012875893665844191303548189492604123505522382770478442837553069890471993483164949504735527438665048438808440494922021062011062567528480025060283867381823427214512155583444236623145440836252289902783715682554658231606320310129833109191138313801289027627739243726679212643242494506530838323607821437997048235272405577079630284307474612832155381483129670050964475785090109743586694668757059662450206919471125303517989042945192886030308203029077484932328302318567286732217365609075794327329327141979774234522455646843538377559711464098301949684161
q = 81090202316656819994650163122592145880088893063907447574390172288558447451623
g = pow(2, p//q, p)
# old
kbits = 150
print('qbits:',bitcount(q),',kbits:',kbits)
y = 4675975961034321318962575265110114310875697301524971406479091223605006115642041321079605682629390144148862285125353335575850114862081357772478008490889403608973023515499959473374820321940514939155187478991555363073408293339373770407404120884229693036839637631846964085605936966005664594330150750220123106270473482589454510979171010750141467635389981140248292523060541588378749922037870081811431605806877184957731660006793364727129226828277168254826229733536459158767652636094988369367622055662565355698632032334469812735980006733267919815359221578068741143213061033728991446898051375393719722707555958912382769606279
h = 88030618649759997479497646248126770071813905558516408828543254210959719582166
r = 34644971883866574753209424578777685962679178432833890467656897732184789528635
s = 19288448359668464692653054736434794709227686774726460500150496018082350808676
x = None
gennew = 0
if gennew:
  # new
  kbits = 150
  q = genqb(256, kbits)
  print('q=', q)
  p = genp(q, 2048)
  print('p=', p)
  g = pow(2,p//q, p)
  print('g=', g)
  x = randint(kbits)
  y = pow(g,x,p)
  print('y=', y)
  k = randint(kbits)
  r = pow(g,k,p) % q
  s = modinv(k,q)*(h + x*r) % q
  print('r=', r)
  print('s=', s)

print(r,s)

def prime_check(p):
  '''Just a simple Fermat test'''
  return pow(2,p,p)==2

# check the parameters
assert prime_check(p)
assert prime_check(q)
assert p % q == 1
assert 1 < g < p
assert pow(g, q, p) == 1

# check the signature
assert isinstance(r, int) and 0 < r < q
assert isinstance(s, int) and 0 < s < q
w = modinv(s,q)
u1 = h * w % q
u2 = r * w % q
gk = pow(g, u1, p) * pow(y, u2, p) % p
assert gk % q == r

print('checked parameter and signature')

# solution
def euclid(a, p):
  """ return (r,u) such that
      a = r/u (mod p) with
      r,u ~ p**0.5"""
  r, s = a, p
  u, v = 1, 0
  while r*r > p:
    q = s // r
    r, s = s - q * r, r
    u, v = v - q * u, u
    assert r == a * u % p
    assert s == a * v % p
  if u < 0:
    return -r, -u
  else:
    return r,u

# We have s * k == h + x * r (mod q)
assert pow(gk,s,p) == pow(g, h, p) * pow(y,r,p) % p

# k = u1 + x * u2 (mod q)
assert gk == pow(g, u1, p) * pow(y, u2, p) % p

start = time()
# k * v = t + x * u (mod q)
u,v = euclid(u2, q)
t = u1 * v % q
# assert pow(gk, v, p) == pow(g, t, p) * pow(y,u,p) % p

print('u',u)
print('v',v)

# Quess m with t + m*q = k*v - u*x
uinv = modinv(u,v)
max_t = 2**kbits*(max(0,v)+max(0,-u))
min_t = 2**kbits*(min(0,v)+min(0,-u))
min_m = (min_t + t)//q
max_m = (max_t + t)//q

if x:
  print(k*v-u*x % q , t)
  m_exp = ((k*v - u*x)-t)//q
  print('m_exp:', m_exp, min_m, max_m)
  assert min_m <= m_exp <= max_m

print('tabsize:', 2**kbits//v)
vTab = {1:0}
gv = pow(g,v,p)
res = 1
print('range:',2**kbits//v+1)
for i in range(2**kbits//v+1):
  if i%500000 == 0:
    print('i:',i)
  res = res * gv % p
  vTab[res] = i+1

expa = -q*uinv % v
mula = pow(g, -expa%q, p)
expb = expa - v
mulb = pow(g, -expb%q, p)

print('search: ',min_m,'..',max_m+1)

for m in range(min_m, max_m+1):
  if m%200000 == 0:
    print('m:',m)
  # x == -(t+m*q)/u % v
  x0 = -(t + m*q) * uinv % v
  if m == min_m:
    gx0 = y * pow(g,-x0 % q,p)%p
  elif x0 - x0old == expa:
    gx0 = gx0 * mula % p
  elif x0 - x0old == expb:
    gx0 = gx0 * mulb % p
  else:
    raise Exception("unexpected")
  x0old = x0
  gv = gx0 % p
  if gv in vTab:
      x = x0 + vTab[gv]*v
      print('m:',m, 'x:', x, 'vtab:', vTab[gv], 'time:', time()-start)
      assert pow(g,x,p) == y
      break
