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
import requests
import ctypes
import gzip
import json
import hashlib
import sys
import string

import solution
from pqcrypto import kyber

N = kyber.lib.KYBER_N
K = kyber.lib.KYBER_K
SSBYTES = kyber.lib.KYBER_SSBYTES
POLYBYTES = kyber.lib.KYBER_POLYBYTES
POLYVECBYTES = kyber.lib.KYBER_POLYVECBYTES
PUBLICKEYBYTES = kyber.lib.KYBER_PUBLICKEYBYTES
SECRETKEYBYTES = kyber.lib.KYBER_SECRETKEYBYTES
CIPHERTEXTBYTES = kyber.lib.KYBER_CIPHERTEXTBYTES


def UnpackSecretKey(packed):
  buf = kyber.ffi.new('uint8_t [{}]'.format(POLYVECBYTES))
  kyber.ffi.buffer(buf)[:] = bytes(packed[:POLYVECBYTES])
  sk = kyber.ffi.new('polyvec*')
  kyber.lib.PQCLEAN_KYBER51290S_CLEAN_polyvec_frombytes(sk, buf)
  return sk


#                             packed SK poly         |           PK                |  hash(PK)
#KYBER_SECRETKEYBYTES:  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)
def PackSecretKey(sk_poly, pk):
  buf = kyber.ffi.new('uint8_t [{}]'.format(SECRETKEYBYTES))
  kyber.lib.PQCLEAN_KYBER51290S_CLEAN_polyvec_tobytes(buf, sk_poly)
  kyber.ffi.buffer(buf)[POLYVECBYTES:POLYVECBYTES + PUBLICKEYBYTES] = bytes(pk)
  h = hashlib.sha256()
  h.update(bytes(pk))
  kyber.ffi.buffer(buf)[POLYVECBYTES + PUBLICKEYBYTES:POLYVECBYTES +
                        PUBLICKEYBYTES + 32] = h.digest()
  return buf


def RecoverSharedSecret(sk, pk, ct_array):
  sk = PackSecretKey(sk, pk)
  ct = kyber.ffi.new('uint8_t [{}]'.format(len(ct_array)))
  kyber.ffi.buffer(ct)[:] = bytes(ct_array)
  ss = kyber.ffi.new('uint8_t [{}]'.format(SSBYTES))
  kyber.lib.PQCLEAN_KYBER51290S_CLEAN_crypto_kem_dec(ss, ct, sk)
  return ss


def WebSanityCheck(port, capture):
  print('Testing web interface at port {}'.format(port))
  host = '127.0.0.1:{0}'.format(port)
  data = requests.get('http://{0}/data'.format(host)).json()
  if not data:
    raise Exception('Failed to read capture {0} metadata'.format(captures[0]))
  ct = binascii.unhexlify(data['Traces'][0]['CT'])
  local_ct = bytes(capture['sessions'][0]['ct'])
  pk = binascii.unhexlify(data['Pk'])
  local_pk = bytes(capture['pk'])
  if ct != local_ct or pk != local_pk:
    raise Exception(
        'Local data did not match server\'s data. Update traces.json.gz in healthcheck'
    )


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--port',
      metavar='P',
      type=int,
      default=1337,
      help='challenge #port. Pass 0 to skip web sanity check.')
  parser.add_argument(
      '--traces',
      type=str,
      default='/home/user/traces.json.gz',
      help='traces json file')
  parser.add_argument(
      '--encaps',
      type=str,
      default='/home/user/encaps.json.gz',
      help='encaps json file')
  parser.add_argument(
      '--window_start',
      type=int,
      default=0,
      help='Samples timeline window to process. Start time.')
  parser.add_argument(
      '--window_size',
      type=int,
      default=50,
      help='Samples timeline window to process. End time. Pass -1 to process all samples.'
  )
  parser.add_argument(
      '--start_coeff',
      type=int,
      default=0,
      help='SK coefficient start index. Must be even.')
  parser.add_argument(
      '--end_coeff',
      type=int,
      default=2,
      help='SK coefficient end index. Must be even. Pass -1 to process all N*K coefficients.'
  )
  parser.add_argument(
      '--recover_flag',
      default=True,
      action='store_true',
      help='Complete KEM decapsulation and recover flag')
  args = parser.parse_args()

  print('Loading encaps file {}'.format(args.encaps))
  with gzip.open(args.encaps, 'r') as f:
    print('Unpacking full secretkey')
    encaps = json.loads(f.read().decode('utf-8'))
    sk = UnpackSecretKey(encaps['sk'])

  print('Loading capture file {}'.format(args.traces))
  with gzip.open(args.traces, 'r') as f:
    capture = json.loads(f.read().decode('utf-8'))

  if args.port != 0:
    WebSanityCheck(args.port, capture)

  cracker = solution.Cracker(capture)

  ntraces, nsamples = cracker.T.shape
  window_start = args.window_start
  window_size = nsamples if args.window_size == -1 else args.window_size
  end_coeff = N * k if args.end_coeff == -1 else args.end_coeff
  for i in range(args.start_coeff, end_coeff, 2):
    # SK is a vector of two polynomials, each with 256 coefficients.
    vec_idx, sk_coeff = i // N, i % N
    a0, a1 = cracker.cpa(i, window_start, window_size)
    assert (a0.value == sk.vec[vec_idx].coeffs[sk_coeff])
    assert (a1.value == sk.vec[vec_idx].coeffs[sk_coeff + 1])
    print('Found correct {0}\'th coefficients ({1}, {2}) at time {3}'.format(
        i, a0.value, a1.value, a0.timestamp))
    window_start = max(a0.timestamp, a1.timestamp)

  if args.recover_flag:
    ss = RecoverSharedSecret(sk, capture['pk'], capture['sessions'][0]['ct'])
    flag_xor_ss = capture['sessions'][0]['flag_xor_ss']
    flag = ''.join([chr(ss[i] ^ flag_xor_ss[i]) for i in range(len(ss))])
    if not (flag.startswith('CTF{') and flag.endswith('}')):
      raise Exception('Failed to recover flag from sk and ss')
    print('Successfully recovered flag')

  return 0


if __name__ == '__main__':
  sys.exit(main())
