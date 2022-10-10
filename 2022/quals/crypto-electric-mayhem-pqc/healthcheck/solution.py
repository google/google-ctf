#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2022 Google LLC
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

import argparse
import collections
import bisect
import binascii
import ctypes
import sys
import string
import numpy as np
from collections import namedtuple
from tqdm import tqdm

from scipy import stats
from pqcrypto import kyber

N = kyber.lib.KYBER_N
K = kyber.lib.KYBER_K
Q = kyber.lib.KYBER_Q
ZETAS = kyber.lib.PQCLEAN_KYBER51290S_CLEAN_zetas
MIN_PCC_SCORE = 0.6
NUM_A1_CANDIDATES = 5
Candidate = namedtuple('Candidate', ('score', 'value', 'timestamp'))

# Hamming Weight Table.
HW = {}
for i in range(-65536, 65537):
  HW[i] = bin(ctypes.c_uint16(i).value).count('1')


# Computes the expected power profile for the given plaintexts and guessed key.
#                      |
# Trace 1: ---___-...,,`````....````.....-----.
#                      |
# Trace 2: --_``-...,,`````----`-``..-..-,...-.
#  .                   |
#  .                   |
# Trace N: -_---.``,,`,`,`-`-.`-.`.`-.`----.`'.
#                      |
#                      |
#                 time t
# At some point in time t, the firmware performs the lookup, and updates one of its
# registers to the sbox value. Every time a bit is changed from a 0 to a 1 (or vice versa),
# some current is required to (dis)charge the data lines. The estimated power consumption at time t,
# is proportional to the Hamming distance from the previous value to the new value. We simplify further,
# and assume the value we're replacing is zero. Then our power model is the hamming weight of the new value.
def fqmul(a, b):
  return kyber.lib.PQCLEAN_KYBER51290S_CLEAN_montgomery_reduce(a * b)


# In this function, we are targeting the first coefficient computation in PQCLEAN_KYBER51290S_CLEAN_basemul.
# Input key is the guess for a[1]. Return value is the power model for the r[0] memory store.
#
# a == skpv
# b == unpacked ciphertext
#
# i=0
#   &a->coeffs[0], &b->coeffs[0]
#       r[0]  = fqmul(a[1], b[1]);  ***
#       r[0]  = fqmul(r[0], zeta);
#       r[0] += fqmul(a[0], b[0]);
#       r[1]  = fqmul(a[0], b[1]);
#       r[1] += fqmul(a[1], b[0]);
#   &a->coeffs[2], &b->coeffs[2]
#       r[2]  = fqmul(a[3], b[3]);  ***
#       r[2]  = fqmul(r[2], zeta);
#       r[2] += fqmul(a[2], b[2]);
#       r[3]  = fqmul(a[2], b[3]);
#       r[3] += fqmul(a[3], b[2]);
# i=1
#   &a->coeffs[4], &b->coeffs[4]
#       r[4]  = fqmul(a[5], b[5]);  ***
#       r[4]  = fqmul(r[4], zeta);
#       r[4] += fqmul(a[4], b[4]);
#       r[5]  = fqmul(a[4], b[5]);
#       r[5] += fqmul(a[5], b[4]);
def LeakModelForA1(a1_guess, a1_coeff, bs):
  # SK is a vector of two polynomials, each with 256 coefficients.
  vec_idx, a1_coeff = a1_coeff // N, a1_coeff % N
  assert (a1_coeff % 2 == 1)
  b1_idx = a1_coeff
  hw = np.zeros(len(bs), dtype=np.float64)
  for i, b in enumerate(bs):
    r0 = fqmul(a1_guess, b.vec[vec_idx].coeffs[b1_idx])
    hw[i] = np.float64(HW[r0])
  return hw


# In this function, we are targeting the second coefficient computation in PQCLEAN_KYBER51290S_CLEAN_basemul.
# Input key is the guess for a[0]. Return value is the power model for the r[1] memory store.
#
# a == skpv
# b == unpacked ciphertext
#
# i=0
#   &a->coeffs[0], &b->coeffs[0]
#       r[0]  = fqmul(a[1], b[1]);
#       r[0]  = fqmul(r[0], zeta);
#       r[0] += fqmul(a[0], b[0]);
#       r[1]  = fqmul(a[0], b[1]);
#       r[1] += fqmul(a[1], b[0]);  ***
#   &a->coeffs[2], &b->coeffs[2]
#       r[2]  = fqmul(a[3], b[3]);
#       r[2]  = fqmul(r[2], zeta);
#       r[2] += fqmul(a[2], b[2]);
#       r[3]  = fqmul(a[2], b[3]);
#       r[3] += fqmul(a[3], b[2]);  ***
# i=1
#   &a->coeffs[4], &b->coeffs[4]
#       r[4]  = fqmul(a[5], b[5]);
#       r[4]  = fqmul(r[4], zeta);
#       r[4] += fqmul(a[4], b[4]);
#       r[5]  = fqmul(a[4], b[5]);
#       r[5] += fqmul(a[5], b[4]);  ***
def LeakModelForA0(a0_guess, a0_coeff, a1, bs):
  # SK is a vector of two polynomials, each with 256 coefficients.
  vec_idx, a0_coeff = a0_coeff // N, a0_coeff % N
  assert (a0_coeff % 2 == 0)
  b0_coeff = a0_coeff
  b1_coeff = a0_coeff + 1
  hw = np.zeros(len(bs), dtype=np.float64)
  for i, b in enumerate(bs):
    r1 = fqmul(a0_guess, b.vec[vec_idx].coeffs[b1_coeff])
    r1 += fqmul(a1, b.vec[vec_idx].coeffs[b0_coeff])
    hw[i] = np.float64(HW[r1])
  return hw


# Decompress ciphertext vector and transform it to NTT domain.
def UnpackCiphertext(packed):
  ct = kyber.ffi.new('uint8_t [{}]'.format(len(packed)))
  kyber.ffi.buffer(ct)[:] = bytes(packed)
  b = kyber.ffi.new('polyvec*')
  kyber.lib.PQCLEAN_KYBER51290S_CLEAN_polyvec_decompress(b, ct)
  kyber.lib.PQCLEAN_KYBER51290S_CLEAN_polyvec_ntt(b)
  return b


# Maintain a sorted list of items with a maximum length.
# https://stackoverflow.com/questions/30443150
def InsertQueue(h, item):
  if len(h) < h.maxlen or item < h[-1]:
    if len(h) == h.maxlen:
      h.pop()
    bisect.insort_left(h, item)


class Cracker(object):

  def __init__(self, capture):
    self.capture = capture
    self.traces = self.capture['sessions']

    print('Unpacking {0} ciphertexts'.format(len(self.traces)))
    self.bs = [UnpackCiphertext(t['ct']) for t in self.traces]

    # Collects all samples in a single m (#traces) by n (#samples) matrix.
    #  _         _
    # | -- T1  -- |
    # | -- T2  -- |
    # | -- ..  -- |
    # | -- TM  -- |
    # |_         _|
    #
    self.T = np.vstack(
        [np.array(t['pm'], dtype=np.float64) for t in self.traces])
    ntraces, nsamples = self.T.shape
    assert (ntraces == len(self.traces))

  # Correlation Power Analysis.
  def cpa(self, sk_coeff, window_start, window_size):
    # Guest two coefficients at a time. Input should be an even index.
    assert (sk_coeff % 2 == 0)
    ntraces, nsamples = self.T.shape
    best_a1 = collections.deque(maxlen=NUM_A1_CANDIDATES)

    window_end = window_start + window_size
    with tqdm(
        desc='Guessing SK[{}]'.format(sk_coeff + 1),
        total=Q,
        bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}| {postfix}',
        postfix=None) as t:
      for key in range(1, Q):
        # Generate hypothetical.
        X = LeakModelForA1(key, sk_coeff + 1, self.bs)
        for i in range(window_start, window_end):
          Y = self.T[:, i]
          assert (X.shape == Y.shape)
          # Pearson correlation coefficient is the normalized covariance between two
          # random variables:
          #  PCC := cov(X,Y) / (sig(X)*sig(Y))
          # The coefficient is in the [-1, 1] range, and is a measure of the linear
          # correlation between the two variables.
          # Values close to +1 or -1 indicate a linear relationship between X and Y.
          # Values close to 0 indicate no relationship between X and Y.
          # https://en.wikipedia.org/wiki/Pearson_correlation_coefficient
          pcc = stats.pearsonr(X, Y)[0]
          if np.isnan(pcc):
            continue
          # Best guess is the key with the highest correlation between all possible keys,
          # across all possible time-slices.
          pcc = np.abs(pcc)
          InsertQueue(best_a1, Candidate(-pcc, key, i))
          t.postfix = {'Window': (window_start, window_end), 'A1': best_a1[0]}
        t.update()

    print('Result: best guess for sk coeff {0} is {1}'.format(
        sk_coeff + 1, best_a1))

    for a1 in best_a1:
      best_a0 = collections.deque(maxlen=1)
      window_start = a1.timestamp
      window_end = window_start + window_size
      with tqdm(
          desc='Guessing SK[{}]'.format(sk_coeff),
          total=Q,
          bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}| {postfix}',
          postfix=None) as t:
        for key in range(1, Q):
          # Generate hypothetical.
          X = LeakModelForA0(key, sk_coeff, a1.value, self.bs)
          for i in range(window_start, window_end):
            Y = self.T[:, i]
            assert (X.shape == Y.shape)
            pcc = stats.pearsonr(X, Y)[0]
            if np.isnan(pcc):
              continue
            pcc = np.abs(pcc)
            InsertQueue(best_a0, Candidate(-pcc, key, i))
            t.postfix = {
                'Window': (window_start, window_end),
                'A1': a1.value,
                'A0': best_a0[0]
            }
          t.update()

      print('Result: best guess for sk coeff {0} is {1}'.format(
          sk_coeff, best_a0))
      if -best_a0[0][0] < MIN_PCC_SCORE:
        print('A0 guess {0} rejected. Low score {1} < {2}'.format(
            best_a0[0].score, best_a0[0].score, MIN_PCC_SCORE))
        continue
      return (best_a0[0], a1)

    raise Exception('Failed to find a0, a1 candidates')
