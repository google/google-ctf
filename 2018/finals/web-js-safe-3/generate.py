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

from z3 import *
import re
import urllib

s = Solver()
SECRET = '_aN7I-ANT1-Ant1-DebUg_'

def Rem(a, b):
  if type(a) == int and type(b) == int:
    return a % b
  else:
    return URem(a, b)

def xor(a, b, offset=0):
  return [c ^ b[(i + offset) % len(b)] for i, c in enumerate(a)], (i + offset) % len(b)

class Template:
  def __init__(self, name, template_str, default_variable = None):
    counter = 0
    self.name = name
    self.chunks = re.split(r'\$\{(.*?)\}', template_str)
    self.vars = {}
    pos = 0
    for i in range(1, len(self.chunks), 2):
      variable = self.chunks[i]
      if len(variable) is 0:
        variable = 'v%s' % counter
        counter += 1
        self.chunks[i] = variable
        self.vars[variable] = default_variable(name, variable)
      else:
        self.vars[variable] = None

  def bytes(self, start=0, end=None):
    bytes = []
    if type(start) == str:
      start = self.chunks.index(start)
    if type(end) == str:
      end = self.chunks.index(end)
    i = start
    while i < (end or len(self.chunks)):
      chunk = self.chunks[i]
      if i % 2 == 0:
        bytes += map(ord, chunk)
      else:
        variable = self.vars[chunk]
        if variable is None:
          print self.vars
          raise Exception('Variable %s in %s is not defined' % (chunk, self.name))
        elif isinstance(variable, list):
          bytes += variable
        elif isinstance(variable, Template):
          bytes += variable.bytes()
        else:
          bytes.append(variable)
      i += 1
    return bytes

  def size(self, start=0, end=None):
    return len(self.bytes(start, end))

  def size_after(self, start=0, end=None):
    if type(start) == str:
      start = self.chunks.index(start) + 1
    else:
      start += 1
    return self.size(start, end)

  def string(self, model):
    s = ''
    for byte in self.bytes():
      if type(byte) is int:
        s += unichr(byte)
      else:
        try:
          s += unichr(model.eval(byte).as_long())
        except:
          print 'Unknown value: %s' % byte
          s += '?'
    return s

  def __repr__(self):
    r = []
    for i, chunk in enumerate(self.chunks):
      if i % 2 == 0:
        r.append(chunk)
      else:
        r.append(self.vars[chunk])
    return 'Template(%s: %s)' % (self.name, r)

def default_variable(template_name, var_name):
  return variable_name(s, template_name + '_' + var_name, 1)[0]

def default_variable_whitespace(template_name, var_name):
  c = BitVec(template_name + '_' + var_name, 8)
  s.add(acceptable_whitespace_char(c), c != ord(' '))
  return c

def minimize(src):
  src = re.sub(
      r'(\w*)\s+',
      lambda m: m.group(0) if (m.group(1) in [
          'function',
          'return',
          'typeof',
          'var',
          'let',
          'throw',
          'delete',
          'new',
      ]) else m.group(1),
      src,
  )
  src = re.sub(r';}', '}', src)
  src = re.sub(r';$', '', src)
  print 'MINIMIZED', src
  return src

def acceptable_flag_char(c):
  return Or([c == ord(i) for i in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_@!?-'])

def acceptable_regexp_char(c):
  return And([c != ord(i) for i in '()[/\\'] + [c >= 0x20])

def acceptable_str_char(c):
  return And([c != ord(i) for i in '\'\\'] + [c >= 0x20])

def acceptable_backtick_char(c):
  return And([c != ord(i) for i in '\`\\\r'])

def between(c, start, end):
  return And(UGE(c, ord(start)), ULE(c, ord(end)))

def acceptable_whitespace_char(c):
  return And(c >= 9, c <= 13)

def non_syntax_error_char(c):
  return Or(
      And(c >= 0x41, c <= 0x5A),
      And(c >= 0x61, c <= 0x7A),
      c & 0x80 == 1
  )

def variable_name(s, name, l=1):
  chars = [BitVec('%s_%s' % (name, x), 8) for x in range(l)]
  scenarios = []
  for start in range(l):
    for end in range(start, l):
      conditions = []
      for i in range(l):
        c = chars[i]
        if i < start or i > end:
          conditions.append(acceptable_whitespace_char(c))
        else:
          conditions.append(Or([
              c == ord('$'),
              between(c, 'A', 'Z'),
              c == ord('_'),
              between(c, 'a', 'z'),
              c & 0x80 == 1,
          ] + ([between(c, '0', '9')] if i != start else [])))
      scenarios.append(And(conditions))
  s.add(Or(scenarios))
  return chars[0] if l == 1 else chars

xor_fn = Template('xor_fn', minimize(
u'''function d(a, b, c) {
    function bytelist(x) {
        if (typeof x == 'function') {
            x = x.toString();
            x = x.slice(x.indexOf('/*') + 2, x.lastIndexOf('*/'));
        }
        if (typeof x == 'string') return x.split('').map(x=>ord(x));
        if (typeof x == 'object') return x;
    }
    a = bytelist(a);
    b = bytelist(b);
    for (var i = 0; i != a.length; i++) {
      debugger;
      c = (c || '') + chr(a[i] ^ b[i%b.length]);
    }
    return eval('eval(c)');
  }'''
))

js = Template(
'main', minimize(
u'''function x(y) {
  ord = Function.prototype.call.bind(''.charCodeAt);
  chr = String.fromCharCode;
  ${xor_fn}
  var data = x=>/*${blob}*/1;
  var k1 = y.charCodeAt(0);
  var k2 = y.charCodeAt(1);
  for (var k3 = 0; k3 < 256; k3++) {
    for (var k4 = 0; k4 < 256; k4++) {
      try {
        return d(data, [k1, k2, k3, k4]);
      } catch(e) {
        console.log('Error:', e);
      }
    }
  }
}'''))
js.vars['xor_fn'] = xor_fn


S1 = Template('S1',
'${prefix}/*${S3_mangled}--*/-:-d-(-${a} =>-/*${S2_enc}*/-${b}-,-d-+-`` ) // ${postfix}'.replace('-', '${}'),
default_variable_whitespace
)
S1.vars['prefix'] = variable_name(s, 'S1_prefix', 3)
S1.vars['a'] = variable_name(s, 'S1_a')
S1.vars['b'] = variable_name(s, 'S1_b')

S2 = Template('S2', minimize(
u'''
try {
  let c = arguments.callee, f = String.fromCharCode;
  if (f((c + '').length % 256) != '${callee_length}') µ;
  if (f((x + '').length % 256) != '${caller_length}') µ;
  if (y != `${flag_0}${flag_1}-''' + SECRET + u'''-${flag_1}${flag_0}`) µ;
  let k = ''.charCodeAt.bind(`${S3_key}`);
  k1 = k(0);
  k2 = k(1);
  k3 = k(2);
  k4 = k(3)-1;
  y = '|:-)'.repeat(75);
} catch(e) {}
throw new SyntaxError;
'''), default_variable)
S2.vars['callee_length'] = BitVec('S2_callee_length', 8)
s.add(acceptable_backtick_char(S2.vars['callee_length']))
s.add(S2.vars['callee_length'] == (xor_fn.size() % 256))
S2.vars['caller_length'] = BitVec('S2_caller_length', 8)
s.add(acceptable_backtick_char(S2.vars['caller_length']))
S2.vars['flag_0'] = BitVec('S2_flag_0', 8)
S2.vars['flag_1'] = BitVec('S2_flag_1', 8)
s.add(acceptable_backtick_char(S2.vars['flag_0']))
s.add(acceptable_backtick_char(S2.vars['flag_1']))
S2.vars['S3_key'] = [BitVec('S2_S3_key_%s' % x, 8) for x in range(4)]
s.add([acceptable_backtick_char(c) for c in S2.vars['S3_key']])
S1.vars['S2_enc'] = [BitVec('S1_S2_enc_%s' % x, 8) for x in range(S2.size())]

S3 = Template('S3', minimize(
u'''
let ${x} = /x/;
${x}.toString = function() {while(1)1};
console.log('', ${x});
/*hide*/
d(x=>/*${S4_enc}*/1, x=>/*${S4_key}*/1)
'''),
default_variable_whitespace
)
S3.vars['x'] = variable_name(s, 'S3_x')
S1_postfix_size = S3.size_after('S4_key')
print 'S1_postfix_size', S1_postfix_size
S1.vars['postfix'] = [BitVec('S1_postfix_%s' % x, 8) for x in range(S1_postfix_size)]
S3_S4_size = S1.size_after('S3_mangled') - S1_postfix_size
print 'S3_S4_size', S3_S4_size
S3.vars['S4_key'] = [BitVec('S3_S4_key_%s' % x, 8) for x in range(S3_S4_size)]
S3.vars['S4_enc'] = [BitVec('S3_S4_enc_%s' % x, 8) for x in range(S3_S4_size)]
S1_S3_mangled_size = S3.size(0, 'S4_key') - S1.size(0, 'S3_mangled')
print 'S1_S3_mangled_size', S1_S3_mangled_size
S1.vars['S3_mangled'] = [BitVec('S3_mangled_%s' % x, 8) for x in range(S1_S3_mangled_size)]

S4_code = minimize(
u'''
y == "|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)|:-)"
'''
)
print S3_S4_size, len(S4_code)
assert S3_S4_size == len(S4_code)
S4 = Template('S4', S4_code + ('/' * (S3_S4_size - len(S4_code))))
assert S4.size() == S3_S4_size

s.check()

# Embedding stage 2 into stage 1
S2_enc = xor(S2.bytes(), xor_fn.bytes())[0]
s.add(map(lambda bytes: bytes[0] == bytes[1], zip(S1.vars['S2_enc'], S2_enc)))

# Embedding stage 4 into stage 3
S4_enc = xor(S4.bytes(), S3.vars['S4_key'])[0]
s.add(map(lambda bytes: bytes[0] == bytes[1], zip(S3.vars['S4_enc'], S4_enc)))

# Encrypting stage 1
S1_key = [BitVec('S1_k%s' % i, 8) for i in range(4)]
S1_enc = xor(S1.bytes(), S1_key)[0]

# Encrypting stage 2
S3_key = [BitVec('S3_k%s' % i, 8) for i in range(4)]
S3_enc = xor(S3.bytes(), S3_key)[0]
s.add(map(lambda bytes: bytes[0] == bytes[1], zip(S2.vars['S3_key'], S3_key)))

# Stage 1 and 3 keys start with the same two bytes and encrypted they are equal
s.add(acceptable_flag_char(S1_key[0]))
s.add(acceptable_flag_char(S1_key[1]))
s.add(acceptable_flag_char(S3_key[0]))
s.add(acceptable_flag_char(S3_key[1]))
s.add(ULE(S1_key[2], 0x70))
s.add(S1_key[2] != 0)
s.add(S1_key[3] != 0)
s.add(S3_key[2] != 0)
s.add(S3_key[3] != 0)
s.add(S1_key[0] < S3_key[0])
assert len(S1_enc) == len(S3_enc)

s.add(map(lambda bytes: bytes[0] == bytes[1], zip(S1_enc, S3_enc)))
js.vars['blob'] = S1_enc
s.add(S2.vars['caller_length'] == (js.size() % 256))

s.add(S2.vars['flag_0'] == S1_key[0])
s.add(S2.vars['flag_1'] == S1_key[1])

# Generate challenge
print s.check()
model = s.model()
print repr(js.string(model)), len(js.string(model))
assert len(re.findall(r'/\*', js.string(model))) == 2
assert len(re.findall(r'\*/', js.string(model))) == 2
print 'S1', repr(S1.string(model))
assert len(re.findall(r'/\*', S1.string(model))) == 2
assert len(re.findall(r'\*/', S1.string(model))) == 2
print 'S2', repr(S2.string(model))
print 'S3', repr(S3.string(model))
assert len(re.findall(r'/\*', S3.string(model))) == 3
assert len(re.findall(r'\*/', S3.string(model))) == 3
print 'S4', repr(S4.string(model))
S1_key = [model[i].as_long() for i in S1_key]
print S1_key, S1_key[0] * 256 * 256 * 256 + S1_key[1] * 256 * 256 + S1_key[2] * 256 + S1_key[3], chr(S1_key[0]), chr(S1_key[1])
S3_key = [model[i].as_long() for i in S3_key]
print S3_key, S3_key[0] * 256 * 256 * 256 + S3_key[1] * 256 * 256 + S3_key[2] * 256 + S3_key[3], chr(S3_key[0]), chr(S3_key[1])
flag = '%s%s-%s-%s%s' % (chr(S1_key[0]), chr(S1_key[1]), SECRET, chr(S1_key[1]), chr(S1_key[0]))
print 'FLAG', repr(flag)
template = open('js_safe_3.template.html', 'rb').read()
payload = 'eval(String.fromCharCode(%s));' % (', '.join(map(str, map(ord, js.string(model)))))
open('js_safe_3.html', 'w').write(template.replace('PAYLOAD', payload))
open('script.js', 'w').write((('r=' + js.string(model).encode('utf-8')) and payload) + ';alert(x(`%s`))' % flag)
