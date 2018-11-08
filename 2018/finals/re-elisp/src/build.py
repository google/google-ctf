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

# Builder that creates the chall.el file from code.txt

flag = "Y0_D4Wg_I_h3Rd_Y0U_lik3_pRoc3SsIng_TexT_sO_1_wRo73_A_73Xt_pR0C3sSOr_1NSId3_4_t3Xt_Pr0C3ssoR"

perm1 = [4, 52, 58, 5, 41, 49, 25, 12, 11, 66, 24, 86, 44, 19, 77, 54, 56, 8, 60, 84, 23, 73, 89, 46, 15, 63, 9, 71, 16, 2, 7, 74, 53, 48, 14, 64, 87, 57, 90, 65, 69, 28, 43, 40, 42, 72, 27, 67, 33, 55, 29, 59, 34, 0, 1, 78, 22, 88, 81, 17, 85, 18, 3, 61, 36, 31, 26, 37, 82, 6, 80, 62, 13, 35, 68, 21, 70, 47, 83, 75, 79, 10, 32, 39, 76, 51, 45, 50, 20, 30, 38]
perm2 = [81, 1, 41, 77, 4, 29, 57, 31, 30, 21, 0, 38, 9, 83, 75, 28, 73, 62, 50, 5, 39, 60, 85, 58, 24, 64, 17, 65, 19, 80, 40, 52, 43, 8, 68, 47, 72, 66, 37, 55, 46, 12, 3, 79, 26, 32, 59, 53, 25, 18, 2, 69, 82, 6, 86, 61, 76, 22, 45, 48, 90, 67, 27, 15, 84, 35, 14, 16, 70, 10, 74, 7, 88, 87, 51, 44, 34, 13, 78, 89, 71, 11, 23, 20, 49, 63, 56, 33, 36, 54, 42]
check_buf = [0x1c, 0xb7, 0x30, 0x74, 0x5d, 0x3d, 0x6e, 0x4d, 0x37, 0x6b, 0x73, 0xf4, 0x34, 0xdb, 0x1c, 0x5e, 0x09, 0xc0, 0x8a, 0x2b, 0x33, 0xeb, 0x78, 0xcd, 0x6c, 0x8b, 0x52, 0x13, 0x70, 0x3f, 0x12, 0xf7, 0x33, 0xe1, 0xb4, 0x8e, 0x1c, 0x40, 0x49, 0xc4, 0x2c, 0x3b, 0x58, 0x48, 0x7a, 0x74, 0xee, 0x48, 0xeb, 0x9f, 0x00, 0x13, 0x0b, 0x3c, 0x33, 0x5c, 0xf0, 0x27, 0x69, 0x6b, 0xbc, 0x48, 0xda, 0xb4, 0x67, 0xd6, 0x0a, 0x4c, 0x5f, 0x4f, 0x5f, 0x44, 0x53, 0xc5, 0x5f, 0x74, 0xb4, 0xb7, 0x15, 0xdb, 0x5f, 0xca, 0xed, 0xe0, 0x11, 0xd8, 0x16, 0xcd, 0x34, 0xf0, 0x5f]

header = """
1. Open this file in Emacs
2. Enter the flag here: CTF{Y0_D4Wg_I_h3Rd_Y0U_lik3_pRoc3SsIng_TexT_sO_1_wRo73_A_73Xt_pR0C3sSOr_1NSId3_4_t3Xt_Pr0C3ssoR}
3. Place your cursor here and press C-M-x
                     |
                     |
+--------------------+
|
|
v
(when t
  (setq max-lisp-eval-depth 200000)
  (setq max-specpdl-size 200000)
  (defun n () (forward-list) (eval-last-sexp nil))
  (defun f (a) (forward-char a) (eval-last-sexp nil))
  (defun b (a) (backward-char a) (eval-last-sexp nil))
  (defmacro fi (c a) `(if ,c (f ,a) (n)))
  (defmacro bi (c a) `(if ,c (b ,a) (n)))
  (defmacro s (r v) `(when t (setq ,r ,v) (n)))
  (defmacro lc (r p) `(s ,r (% (char-after (1+ ,p)) 256)))
  (defmacro si (v i r) `(when t (aset ,v ,i ,r) (n)))
  (defmacro li (r v i) `(s ,r (aref ,v ,i)))
  (defun p (m) (delete-and-extract-region $code_start$ (1+ (buffer-size))) (insert m))
  (f $$$$))

""".lstrip()
code_start = header.find('(when t')
header = header.replace('$code_start$', str(code_start + 1))

# Comment this to keep the flag in the file.
header = header.replace(flag, 'X'*len(flag))

constants = {}
flag_start = 'CTF{'
constants['flag'] = header.find(flag_start)+len(flag_start)


constants['perm2'] = len(header)
for i in perm2:
  header += chr(i)
constants['check_buf'] = len(header)
for i in check_buf:
  header += chr(i)
constants['perm1'] = len(header)
for i in perm1:
  header += chr(i)
# header += '\n'

with open ("code-obf.txt", "r") as f:
  content=f.read().strip()

code = ""
for line in content.split("\n"):
  if not line.startswith(';;') and len(line) > 0:
    code += line + '\n'
code = code.replace('\n', '')

# print code
# print "---------"

def findparend(code, start):
  if code[start] != '(':
    return start
  count = 1
  for i in xrange(start+1, len(code)):
    if code[i] == '(':
      count += 1
    elif code[i] == ')':
      count -= 1
    if count == 0:
      return i
  print "par end not found :C"
  exit(0)

jump_len = 4

code2 = header
i = 0
labels = {}
jumps = {}
while i < len(code):
  c = code[i]
  if c == '~': # Labels
    next = code.find('~', i+1)
    # print code[i+1:next]
    labels[code[i+1:next]] = len(code2)
    i = next+1
    continue

  if c == '$': # Constants
    next = code.find('$', i+1)
    const_name = code[i+1:next]
    if const_name not in constants:
      print const_name+" not in constants :C"
      exit(0)
    code2 += str(constants[const_name])
    i = next+1
    continue

  if code[i:].startswith('(j'):
    end = findparend(code, i)
    # print code[i:end+1]
    beg = code.rfind(' ', 0, end)
    label = code[beg+1:end]
    # print label

    if label in labels:
      code2 += '(b'
    else:
      code2 += '(f'
    code2 += code[i+2:beg+1]
    jumps[len(code2)] = label
    code2 += 'X'*jump_len + ')'

    i = end+1
    continue

  i += 1
  code2 += c

if "start" not in labels:
  print "start not in labels :C"
  exit(0)

start_str = str(labels["start"] - code_start).rjust(4)
code2 = code2.replace("$$$$", start_str)

# print code2
# print "---------"
# print labels
# print jumps
# print "---------"

for place, label in jumps.iteritems():
  if label not in labels:
    print label +" not in labels :C"
    exit(0)
  dest = labels[label]
  dest = abs(place + jump_len + 1 - dest)
  dest_str = str(dest).rjust(jump_len)
  # print dest_str
  # print label
  # print code2[place:place+jump_len]
  code2 = code2[:place] + dest_str + code2[place+jump_len:]

# print code2

with open("chall.el", "w") as f:
  f.write(code2+"\n")
