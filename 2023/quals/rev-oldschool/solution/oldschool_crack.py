#!/usr/bin/env python3
# Copyright 2023 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     https://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------------------
# Google CTF 2023: Old School Crack
# ----------------------------------------------------------------------------------------
import math
import numpy
import random
import string

from typing import List


sbox = [
    16, 14, 13, 2,  11, 17, 21, 30,
    7,  24, 18, 28, 26, 1,  12,  6, 
    31, 25, 0,  23, 20, 22, 8,  27,
    4,  3,  19, 5,  9,  10, 29, 15
]

xor_array = [
    25,  2,  8, 15, 10, 26, 13, 30,
     4,  5, 16,  7, 14,  0,  6, 31,
    29, 11, 17,  3, 28, 19,  9, 20,
    27, 21,  1, 12, 24, 22, 23, 18
]

feistel_key_triplets = [
    [ 3, 10, 22],
    [ 4, 12, 16],
    [20, 13, 22],
    [13, 22, 19],
    [14, 13, 12],
    [23,  7, 19],
    [14, 20,  1],
    [11,  7, 24],
    [25, 11, 13],
    [ 8, 9,   1],
    [12, 7,  20],
    [21, 19, 16],
    [ 6, 23,  7],
    [10, 18, 17],
    [ 2, 11,  4],
    [ 3, 10, 12],
    [ 5, 26,  8],
    [ 6, 15,  4],
    [10,  0, 15],
    [ 1, 14,  9],
    [11,  7,  1],
    [25,  1, 23],
    [ 1,  9, 24],
    [15, 23, 19],
    [16, 22, 15],
    [12,  4, 23],
    [19, 24,  5],
    [19,  8, 13],
    [18,  1, 21],
    [ 7,  4, 19],
    [25,  8, 17],
    [14,  6, 23]
]


# Left Rotate and Feistel round function helpers.
ROL = lambda n, c, b: ((n << c) | (n >> (b - c))) & ((1 << b) - 1)
F   = lambda r, k, keylen: ROL(r, 3, 15) ^ ~ROL(k, 1, keylen)


# ----------------------------------------------------------------------------------------
# Modular Matrix Inversion (Helper).
#
# Code taken from: https://stackoverflow.com/questions/4287721
# Also: https://www.dcode.fr/matrix-inverse
# ----------------------------------------------------------------------------------------
def mod_inv(a, p):
  """Finds the inverse of `a` modulo `p` (if it exists)."""
  for i in range(1, p):  # Naive approach.
    if (i * a) % p == 1:
      return i

  raise Exception(f'Number {a} does not have an inverse modulo {p}')


def minor(mat, i, j):
  """Returns matrix A with the i-th row and j-th column deleted."""
  minor = numpy.zeros(shape=(len(mat) - 1, len(mat) - 1))
  mat = numpy.array(mat)  
  p = 0

  for s in range(0, len(minor)):
    if p == i:
      p += 1
    q = 0

    for t in range(0, len(minor)):
      if q == j:
        q += 1
      minor[s][t] = mat[p][q]
      q += 1
    p += 1

  return minor


def calc_matrix_mod_inv(mat: List[List[int]], p: int) -> List[List[int]]:
  """Finds the inverse of matrix `mat modulo `p`."""  
  mat = numpy.matrix(mat)
  n = len(mat)
  adj = numpy.zeros(shape=(n, n))
  
  for i in range(0, n):
    for j in range(0, n):
      adj[i][j] = ((-1) ** (i + j) * int(round(numpy.linalg.det(minor(mat, j, i))))) % p
  
  inv = (mod_inv(int(round(numpy.linalg.det(mat))), p) * adj) % p
  # Convert array of floats to list of ints.
  return [[int(v) for v in row] for row in inv]


# ----------------------------------------------------------------------------------------
# Keygen Part: Find the password given the username.
# ----------------------------------------------------------------------------------------
def usr_to_matrix_fwd(usr: str) -> List[List[int]]:
  """Transforms a username into a matrix (FORWARD ALGORITHM)."""
  assert len(usr) == 20

  p = 31337
  feistel_key = ''
  usrcols = 0
  keylen = 0
  usrmat = []

  for i in range(0, len(usr), 4):
    b = (((usr[i + 0] & 0x7F) << 21) |
         ((usr[i + 1] & 0x7F) << 14) |
         ((usr[i + 2] & 0x7F) <<  7) |
          (usr[i + 3] & 0x7F))
    b = f'{b:028b}'  
    t = feistel_key_triplets[p % 32]
       
    feistel_key += b[27 - t[0]] + b[27 - t[1]] + b[27 - t[2]]

    b = int(b, 2)
    for k in range(3):
      q = feistel_key_triplets[p % 32][k]
      b = ((b >> (q + 1)) << q) | (b & ((1 << q) - 1));            
   
    b = f'{b:025b}'

    for k in range(1 + (int(feistel_key, 2) & 7)):
      p = (8121 * p + 28411) % 134456  # LCG update.
      
    usrmat.append([~int(b[k:k + 5], 2) & 0x1F for k in range(0, 25, 5)][::-1])
  
    keylen += 3  
    usrcols += 1    

  feistel_key = int(feistel_key, 2)

  # print(f'Feistel Key: 0x{feistel_key:X}', 'keylen:', keylen)
  # print('Before Matrix:', usrmat)

  # Do the Feistel encryption.
  for i in range(usrcols):
    L = usrmat[0][i] | (usrmat[1][i] << 5) | ((usrmat[2][i] & 3) << 10)
    R = ((usrmat[2][i] & 0x1C) >> 2) | (usrmat[3][i] << 3) | (usrmat[4][i] << 8)
   
    for j in range(13):
      t = L ^ F(R, feistel_key, keylen)
      L = R & 0x7FFF;
      R = t & 0x7FFF;

    usrmat[0][i] = L & 0x1F
    usrmat[1][i] =  (L >>  5) & 0x1F
    usrmat[2][i] = ((L >> 10) & 0x3) | (R & 0x1C)
    usrmat[3][i] =  (R >>  5) & 0x1F
    usrmat[4][i] =  (R >> 10) & 0x1F

  # print('Username Matrix:', usrmat)
  return usrmat


# ----------------------------------------------------------------------------------------
def matrix_to_pwd_bwd(usrmat: List[List[int]]) -> str:
  """Transforms a matrix to a password (BACKWARD ALGORITHM)."""
  usrmat = [[int(r) for r in row] for row in usrmat]  # Float to int.

  # Shift columns to the right.
  usrmat[1] = usrmat[1][4:] + usrmat[1][:4]
  usrmat[2] = usrmat[2][3:] + usrmat[2][:3]
  usrmat[3] = usrmat[3][2:] + usrmat[3][:2]
  usrmat[4] = usrmat[4][1:] + usrmat[4][:1]

  for i in range(5):
    for j in range(5):
      usrmat[i][j] ^= xor_array[i*5 + j]

  # Build inverse S-Box.
  inv_sbox = [-1]*32
  for i in range(32):
    inv_sbox[sbox[i]] = i

  for i in range(5):
    for j in range(5):
      usrmat[i][j] = inv_sbox[usrmat[i][j]]

  # Map matrix back to password form.
  pwd = [
    ''.join('23456789ABCDEFGHJKLMNPQRSTUVWXYZ'[usrmat[i][j]]
    for j in range(5))
    for i in range(5)
  ]

  return '-'.join(pwd)


# ----------------------------------------------------------------------------------------
# Test Only.
# ----------------------------------------------------------------------------------------
def pwd_to_matrix_fwd(pwd: str) -> List[List[int]]:
  """Transforms a password into a matrix (FORWARD ALGORITHM)."""
  pwmat = []

  # Sanity checks.
  assert len(pwd) == 29
  assert pwd[5] == '-' and pwd[11] == '-' and pwd[17] == '-' and pwd[23] == '-'

  for p in pwd.split('-'):
    # If we have an invalid character this will raise a ValueError
    pwmat.append(['23456789ABCDEFGHJKLMNPQRSTUVWXYZ'.index(k) for k in p])

  for i in range(5):
    for j in range(5):
      pwmat[i][j] = sbox[pwmat[i][j]];
      pwmat[i][j] ^= xor_array[i*5 + j];

  # Shift rows.
  pwmat[1] = pwmat[1][1:] + pwmat[1][:1]
  pwmat[2] = pwmat[2][2:] + pwmat[2][:2]
  pwmat[3] = pwmat[3][3:] + pwmat[3][:3]
  pwmat[4] = pwmat[4][4:] + pwmat[4][:4]

  # print('Password Matrix:', pwmat)
  return pwmat


# ----------------------------------------------------------------------------------------
def crack_pwd_from_usr(usr: str) -> str:
  """Cracks the password from a given username."""  
  # Step 1: Apply forward algorithm to get username matrix.
  usrmat = usr_to_matrix_fwd(usr)

  # Step 2: Find the modular inverse of the username matrix.
  # If it does not exist, an exception will be raised.
  invmat = calc_matrix_mod_inv(usrmat, 32)
  
  # Step 3: Apply backward algorithm to get the password from inverse matrix.
  pwd = matrix_to_pwd_bwd(invmat)

  return pwd


# ----------------------------------------------------------------------------------------
def main() -> None:
  print('[+] Old School Crack Started.')

  # Fix the constant arrays that modified in Anti-Debugging checks.
  for q in range(32):
      xor_array[q] ^= 0x2

      feistel_key_triplets[q][0], feistel_key_triplets[q][1] = (
        feistel_key_triplets[q][1], feistel_key_triplets[q][0])


  # Generate 50 random usernames and find the corresponding password for each of them.
  pairs = [('ispoleetmoreyeah1338', 'D78UE-UJF6Y-VLYWY-X2F8J-STPA3')]

  for i in range(49):
    while True:
      usr = ''.join(random.choice(string.ascii_letters) for i in range(20))      
      try:
        pwd = crack_pwd_from_usr(usr.encode('utf-8'))      
        pairs.append((usr, pwd))
        break
      except Exception:
        # print(f'There is no password for username: {usr}')
        pass

  print('[+] Generated username/password pairs:')
  for u, p in pairs:
    print(f"('{u}', '{p}'),")

  print('[+] Generated usernames only:')
  for u, p in pairs:
    print(f"('{u}', '{{password}}'),")

  print('[+] Program finished! Bye bye :)')


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
  main()

