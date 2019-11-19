# Copyright 2019 Google LLC
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


from sage.misc.persist import SagePickler

import struct
# import solve
import random

class Shifter(object):
  def __init__(self, initial_state):
    self.idx = 0
    self.state = initial_state.copy()

  def run_row(self):
    for i in range(1,len(self.state)):
      # self.state[i] = self.state[i] ^^ (self.state[i-1]>>62) ^^ self.state[i-1]
      self.state[i] = (
          self.state[i] ^^ (
            (self.state[i-1] ^^ (self.state[i-1]>>62)) ^^ (
              (self.state[i-1] >> 32 ) & 0xdeadbeef)
            # ^^ key[i] ^^
           ))
    self.finish()

  def finish(self):
    self.state[0] ^^= self.state[len(self.state)-1]

BITS = 64
K = 1337
NN = 312
MM = NN//2
PSIZE = NN * BITS
NSAMPLES = (NN + 2) * BITS

X = zero_matrix(GF(2), PSIZE, NSAMPLES)
Y = zero_matrix(GF(2), PSIZE, NSAMPLES)

import IPython

def fill_solve_vector(state, v, idx):
  for j, s in enumerate(state):
    v[j*BITS:(j+1)*BITS, idx] = to_bitvec(s)

def fsv(state):
  v = zero_vector(GF(2), PSIZE)
  for j, s in enumerate(state):
    v[j*BITS:(j+1)*BITS] = to_bitvec(s)
  return v

def vsf(v):
  state = [0]*NN
  for j,_ in enumerate(state):
    state[j] = from_bitvec(list(v[j*BITS:(j+1)*BITS]))
  return state

def to_list(b):
  return [x[0] for x in b]

def extract_state(v, idx):
  state = [0]*NN
  for j,_ in enumerate(state):
    state[j] = from_bitvec(to_list(list(v[j*BITS:(j+1)*BITS, idx])))
  return state


from tqdm import tqdm

def jumble(key):
  init_state = [0] * len(key)
  for i, _  in enumerate(key):
    init_state[(i+1)%NN] ^^= key[i]
  jumbler = Shifter(init_state)
  for i in range(1, len(init_state)):
    jumbler.state[i] ^^= jumbler.state[i-1]
  for i in range(K):
    jumbler.run_row()
  return jumbler.state

## Old way of generating the matrix.
# for i in tqdm(range(NSAMPLES)):
#   init_state = [random.randint(0, 2**BITS) for _ in range(NN)]
#   fill_solve_vector(init_state, X, i)
#   # TODO: Do this k times
#   js = jumble(init_state)
#   fill_solve_vector(js, Y, i)

## New way of generating the matrix from precomputed rust data.
startf = open('start','rb')
endf = open('end','rb')
for i in tqdm(range(NSAMPLES)):
  startb = startf.read(NN*8)
  init_state = struct.unpack("<{}Q".format(NN), startb)
  fill_solve_vector(init_state, X, i)
  endb = endf.read(NN*8)
  js = struct.unpack("<{}Q".format(NN), endb)
  if i == 0:
    assert(list(js) == jumble(list(init_state)))
  fill_solve_vector(js, Y, i)

# Challenge
challenge = [random.randint(0, 2**BITS) for _ in range(NN)]
solution = jumble(challenge)

PP = X.solve_left(Y)

print(">> PPR: {}".format(PP.rank()))
assert (vsf(PP.inverse() * fsv(solution)) == challenge)
assert (vsf(PP * fsv(challenge)) == solution)

save(PP.inverse(), 'pp.sobj')

def untemper(x):
  x ^^=  x >> 43;
  x ^^= (x << 37) & 0xFFF7EEE000000000;
  x ^^= (x << 17) & 0x00000003eda60000;
  x ^^= (x << 17) & 0x00067ffc00000000;
  x ^^= (x << 17) & 0x71d0000000000000;
  x ^^= (x >> 29) & 0x0000000555555540;
  x ^^= (x >> 29) & 0x0000000000000015;
  return x

def m_patch(point):
  rev = list(map(untemper, point))
  srev = [0] * MM + rev + [0]*(MM - len(rev))
  return vsf(PP.inverse() * fsv(srev))

import struct
import base64

def format_patch(ints):
  return base64.b64encode(struct.pack("<%dQ"%len(ints), *ints))

IPython.embed()
