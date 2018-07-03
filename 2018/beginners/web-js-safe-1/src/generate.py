#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2018 Google LLC
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

import hashlib

m = hashlib.sha256()
m.update('Passw0rd!')
secret_hash = map(ord, m.digest())

def var():
  env.append(None)
  return len(env) - 1

def instr(fn, arg1, arg2, result=None, lhs = None):
  if lhs is None:
    lhs = len(env)
    env.append(result)
  else:
    env[lhs] = result
  code.append([lhs, fn, arg1, arg2])
  print_instr(**locals())
  return lhs

def print_instr(fn, arg1, arg2, result, lhs):
  def var(index):
    if env[index] is None:
      return 'x%d' % index
    else:
      return 'x%s=%s' % (index, repr(env[index]))
  lhs = 'x%d' % lhs
  fn = ['get_attr', 'apply', 'add', 'chr'][fn] if fn < 4 else var(fn)
  arg1 = var(arg1)
  arg2 = var(arg2)
  result = '?' if result is None else result
  print '%s = %s(%s, %s) = %s' % (lhs, fn, arg1, arg2, result)

def number(n):
  if n in env:
    return env.index(n)
  else:
    if (n&(n-1)) == 0:
      return instr(add, number(n/2), number(n/2), n)
    for i, c in enumerate(bin(n)[2:][::-1]):
      if c == '1':
        return instr(add, number(n - (2**i)), number(2**i), n)

def zero(var):
  to_zero.append(var)
  return var

def string(s):
  if s in env or s in map(str,[0,1,2,3,4,5,6,7,8,9]):
    return env.index(s if s in env else int(s))
  else:
    if len(s) == 1:
      n = number(ord(s))
      return instr(chr, n, 0, s)
    else:
      cached = s[:-1] in env
      prefix = string(s[:-1])
      return zero(instr(add, prefix, string(s[-1]), s, None if cached else prefix))

def get(obj, prop):
  return zero(instr(get_attr, obj, string(prop)))

def fn(code):
  return zero(instr(get(get_attr, 'constructor'), string('x'), string(code)))

def pair(a, b):
  return zero(instr(array, a, b))

def hash(text):
  crypto = get(window, 'crypto')
  subtle = get(crypto, 'subtle')
  digest = get(subtle, 'digest')
  hash_method = string('sha-256')
  digest_args = pair(hash_method, password)
  apply_args = pair(subtle, digest_args)
  result = zero(instr(apply, digest, apply_args))
  return result

alphabet = map(
    unichr,
    range(ord(u'a'), ord(u'z')) +
    range(ord(u'A'), ord(u'Z')) +
    range(ord(u'\u0400'), ord(u'\u04FF'))
) 
def final_code():
  result = u''
  for line in code:
    for c in line:
      result += alphabet[c]
  return result

env = []
code = []

get_attr = var()
apply = var()
add = var()
chr = var()
env.append(0)
env.append(1)
password = var()
out = var()
#log = var()

to_zero = []

# Pre-warm string and number cache
for i in range(len(secret_hash)):
  number(i)
for n in secret_hash:
  number(n)
zero(string('return '))

window = zero(instr(fn('return window'), string('x'), string('x')))
array = get(window, 'Array')
xor = fn('return x[0]^x[1]')
bit_or = fn('return x[0]|x[1]')
h = hash(password)
h = zero(instr(get(window, 'Uint8Array'), h, string('x')))

n = instr(add, env.index(0), env.index(0), 0)
pair_to_compare = zero(instr(add, env.index(0), env.index(0), 0))
pair_to_or = zero(instr(add, env.index(0), env.index(0), 0))
equal = instr(add, env.index(0), env.index(0), 0)
#instr(log, string('hash:'), h)
for i, x in enumerate(secret_hash):
  instr(get_attr, h, number(i), None, n)
  instr(array, n, number(secret_hash[i]), None, pair_to_compare)
  #instr(log, string('compare:'), pair_to_compare)
  instr(xor, pair_to_compare, string('x'), None, equal)
  instr(array, out, equal, None, pair_to_or)
  instr(bit_or, pair_to_or, string('x'), None, out)

for x in set(to_zero):
  instr(add, env.index(0), env.index(0), 0, x)

print 'out', out, alphabet[out]
print 'array', array, alphabet[array]
print 'xor', xor, alphabet[xor]
print 'bit_or', bit_or, alphabet[bit_or]
print 'h', h, alphabet[h]

print env
print code
c = final_code()
print len(c), repr(final_code())
