#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
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

import concurrent.futures
import argparse
import pwnlib
import challenge_pb2
import json
import struct
import sys
import collections

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec

import ecdsa

FLAG_CIPHER_KDF_INFO = b'Flag Cipher v1.0'
FLAG_MAC_KDF_INFO = b'Flag MAC v1.0'

CHANNEL_CIPHER_KDF_INFO  = b'Channel Cipher v1.0'
CHANNEL_MAC_KDF_INFO = b'Channel MAC v1.0'

# Copied from http://www.secg.org/SEC2-Ver-1.0.pdf
P224_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001
P224_A = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE
P224_B = 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4
P224_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
P224_GX = 0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21
P224_GY = 0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34


IV = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'

Res = collections.namedtuple('Res', ['residue', 'modulo'])

CACHED_RESIDUES = [Res(153, 1319), Res(177, 1811), Res(262, 1361), Res(142, 1117), Res(246, 1801),
    Res(669, 1427), Res(732, 1733), Res(618, 1951), Res(372, 1087), Res(513, 1381), Res(605, 1259),
    Res(52, 1223), Res(484, 1481), Res(138, 1709), Res(2, 1621), Res(391, 1549), Res(43, 1367),
    Res(108, 1109), Res(378, 1657), Res(696, 1877), Res(60, 1181), Res(66, 1031)]
CACHED_OFFLINE_START_ROUND = 4170000


def handle_pow(tube):
    tube.recvuntil(b'python3 ')
    tube.recvuntil(b' solve ')
    challenge = tube.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    tube.sendline(solution)
    tube.recvuntil(b'Correct\n')

def read_message(tube, typ):
  n = struct.unpack('<L', tube.recvnb(4))[0]
  buf = tube.recvnb(n)
  msg = typ()
  msg.ParseFromString(buf)
  return msg

def write_message(tube, msg):
  buf = msg.SerializeToString()
  tube.send(struct.pack('<L', len(buf)))
  tube.send(buf)

def curve2proto(c):
  if c.name == 'secp224r1':
    return challenge_pb2.EcdhKey.CurveID.SECP224R1
  elif c.name == 'secp256r1':
    return challenge_pb2.EcdhKey.CurveID.SECP256R1
  else:
    raise Exception('unsupported curve %s' % (c.name))

def key2proto(key):
  assert(isinstance(key, ec.EllipticCurvePublicKey))
  out = challenge_pb2.EcdhKey()
  out.curve = curve2proto(key.curve)
  x, y = key.public_numbers().x, key.public_numbers().y
  out.public.x = x.to_bytes((x.bit_length() + 7) // 8, 'big')
  out.public.y = y.to_bytes((y.bit_length() + 7) // 8, 'big')
  return out

def proto2key(key):
  assert(isinstance(key, challenge_pb2.EcdhKey))
  assert(key.curve == challenge_pb2.EcdhKey.CurveID.SECP224R1)
  curve = ec.SECP224R1()
  x = int.from_bytes(key.public.x, 'big')
  y = int.from_bytes(key.public.y, 'big')
  public = ec.EllipticCurvePublicNumbers(x, y, curve)
  return ec.EllipticCurvePublicKey.from_encoded_point(curve, public.encode_point())

def json2proto(point):
  out = challenge_pb2.EcdhKey()
  out.curve = challenge_pb2.EcdhKey.CurveID.SECP256R1
  x, y = point['gx'], point['gy']
  out.public.x = x.to_bytes((x.bit_length() + 7) // 8, 'big')
  out.public.y = y.to_bytes((y.bit_length() + 7) // 8, 'big')
  return out


# Chinese Remainder Theorem (CRT) for two moduli.
# Returns x in Z*_(n1*n2) such that:
#
#   a1 == x mod n1
#   a2 == x mod n2
#
def CRT2(r1, r2):
  a1 = r1.residue
  n1 = r1.modulo
  a2 = r2.residue
  n2 = r2.modulo
  # Use explicit formula.
  # https://en.wikipedia.org/wiki/Chinese_remainder_theorem#Case_of_two_moduli
  x = pow(n1, -1, n2) * a2 * n1 + pow(n2, -1, n1) * a1 * n2
  x %= (n1 * n2);
  return x

## Chinese Remainder Theorem (CRT) for a set of moduli.
## Returns x in Z*_(n1*n2...*nk) such that:
##
##   a1 == x mod n1
##   a2 == x mod n2
##   ...
##   ak == x mod nk
##
## ns should be pair-wise coprime.
## |equations| should not be empty.
def CRT(equations):
  current = equations[0]
  for nxt in equations[1:]:
    r = CRT2(current, nxt)
    n = current.modulo * nxt.modulo
    current = Res(r, n)
  return current.residue


class AuthCipher(object):
  def __init__(self, secret, cipher_info, mac_info):
    self.cipher_key = self.derive_key(secret, cipher_info)
    self.mac_key = self.derive_key(secret, mac_info)

  def derive_key(self, secret, info):
    hkdf = HKDF(
         algorithm=hashes.SHA256(),
         length=16,
         salt=None,
         info=info,
    )
    return hkdf.derive(secret)

  def encrypt(self, iv, plaintext):
    cipher = Cipher(algorithms.AES(self.cipher_key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext) + encryptor.finalize()

    h = hmac.HMAC(self.mac_key, hashes.SHA256())
    h.update(iv)
    h.update(ct)
    mac = h.finalize()

    out = challenge_pb2.Ciphertext()
    out.iv = iv
    out.data = ct
    out.mac = mac
    return out

class Attacker(object):
  def __init__(self, port, json_file):
    with open(json_file, 'rt') as f:
      self.points = json.loads(f.read())
    for p in self.points:
      p['n'], p['gx'], p['gy'] = map(int, [p['n'], p['gx'], p['gy']])
    self.port = port

  def get_encrypted_flag(self):
    print('Getting encrypted flag')
    tube = pwnlib.tubes.remote.remote('127.0.0.1', self.port)
    tube.recvuntil('== proof-of-work: ')
    if tube.recvline().startswith(b'enabled'):
        handle_pow(tube)

    server_hello = read_message(tube, challenge_pb2.ServerHello)
    self.server_key = proto2key(server_hello.key)
    self.encrypted_flag_data = server_hello.encrypted_flag.data
    self.encrypted_flag_iv = server_hello.encrypted_flag.iv
    self.encrypted_flag_mac = server_hello.encrypted_flag.mac

  def sanity_check_valid_session(self):
    print('Establishing a valid session, and running sanity checks')
    tube = pwnlib.tubes.remote.remote('127.0.0.1', self.port)
    tube.recvuntil('== proof-of-work: ')
    if tube.recvline().startswith(b'enabled'):
        handle_pow(tube)

    server_hello = read_message(tube, challenge_pb2.ServerHello)
    server_key = proto2key(server_hello.key)

    # Establish a normal session with a valid SECP224 point.
    private_key = ec.generate_private_key(ec.SECP224R1())
    client_hello = challenge_pb2.ClientHello()
    client_hello.key.CopyFrom(key2proto(private_key.public_key()))

    write_message(tube, client_hello)

    shared_key = private_key.exchange(ec.ECDH(), server_key)

    channel = AuthCipher(shared_key, CHANNEL_CIPHER_KDF_INFO, CHANNEL_MAC_KDF_INFO)
    msg = challenge_pb2.SessionMessage()
    msg.encrypted_data.CopyFrom(channel.encrypt(IV, b'hello'))
    write_message(tube, msg)

    # Verify data is echoed back.
    reply = read_message(tube, challenge_pb2.SessionMessage)
    assert(len(reply.encrypted_data.data) > 0)

    # Verify server authenticates message.
    msg.encrypted_data.iv = b'\xff' + IV[1:]
    write_message(tube, msg)

    reply = read_message(tube, challenge_pb2.SessionMessage)
    assert(len(reply.encrypted_data.data) == 0)

  def collect_modular_residue(self, point):
    print('Collecting modular residue for point of order %d' % (point['n']))
    tube = pwnlib.tubes.remote.remote('127.0.0.1', self.port)
    tube.recvuntil('== proof-of-work: ')
    if tube.recvline().startswith(b'enabled'):
        handle_pow(tube)

    server_hello = read_message(tube, challenge_pb2.ServerHello)
    server_key = proto2key(server_hello.key)

    # Establish a session with an invalid SECP224 point.
    client_hello = challenge_pb2.ClientHello()
    client_hello.key.CopyFrom(json2proto(point))

    write_message(tube, client_hello)

    curve = ecdsa.ellipticcurve.CurveFp(P224_P, P224_A, P224_B)
    setattr(curve, 'contains_point', lambda x,y: True)
    x, y = point['gx'] % P224_P, point['gy'] % P224_P
    base = ecdsa.ellipticcurve.Point(curve, x, y)

    for i in range(1, point['n']):
      shared_point = base*i
      shared_key = shared_point.x().to_bytes((shared_point.x().bit_length() + 7) // 8, 'big')

      channel = AuthCipher(shared_key, CHANNEL_CIPHER_KDF_INFO, CHANNEL_MAC_KDF_INFO)
      msg = challenge_pb2.SessionMessage()
      msg.encrypted_data.CopyFrom(channel.encrypt(IV, b'hello'))
      write_message(tube, msg)

      reply = read_message(tube, challenge_pb2.SessionMessage)
      if len(reply.encrypted_data.data) > 0:
        print('Found modular residue %d for prime %d' % (i, point['n']))
        return (i, point['n'])

    raise Exception('Failed to find modular residue for point %r' % (point))

  def online_step(self, num):
    self.get_encrypted_flag()
    self.sanity_check_valid_session()

    self.residues = set(CACHED_RESIDUES)
    for i, p in enumerate(self.points):
      if i == num:
        break
      self.residues.add(self.collect_modular_residue(p))

    # No new results.
    assert(len(self.residues) == len(CACHED_RESIDUES))
    self.residues = list(self.residues)
    self.residues.sort(key=lambda x: x[1])

  def offline_step(self):
    print('Starting offline step with %d residues' % (len(self.residues)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
      future_to_round = {}

      num_bits = len(self.residues)
      # Uncomment to run full brute force search.
      # for i in range(2**num_bits):
      for i in range(CACHED_OFFLINE_START_ROUND, 2**num_bits):
        if i % 1000 == 0:
          print('Done submitting round #', i)
          for future in concurrent.futures.as_completed(future_to_round):
            flag = future.result()
            if flag:
              assert(flag.startswith(b'CTF{'))
              assert(flag.endswith(b'}'))
              return
          future_to_round = {}
          print('Done clearing queue')
        future_to_round[executor.submit(self.test_round_residues, i, num_bits)] = i

      for future in concurrent.futures.as_completed(future_to_round):
        flag = future.result()
        if flag:
          assert(flag.startswith(b'CTF{'))
          assert(flag.endswith(b'}'))
          return

    raise Exception('Failed to recover private key')

  def test_round_residues(self, round_num, num_bits):
    round_residues = []
    for bit in range(num_bits):
      r, n = self.residues[bit]
      if round_num & (1<<bit):
        round_residues.append(Res(r, n))
      else:
        round_residues.append(Res(n-r, n))

    # reassemble private from residues.
    private_key = CRT(round_residues)
    private_key %= P224_N

    # test if key recovers encrypted flag.
    secret = private_key.to_bytes((private_key.bit_length() + 7) // 8, 'big')
    flag_cipher = AuthCipher(secret, FLAG_CIPHER_KDF_INFO, FLAG_MAC_KDF_INFO)

    h = hmac.HMAC(flag_cipher.mac_key, hashes.SHA256())
    h.update(self.encrypted_flag_iv)
    h.update(self.encrypted_flag_data)
    mac = h.finalize()

    if mac != self.encrypted_flag_mac:
      return None

    cipher = Cipher(algorithms.AES(flag_cipher.cipher_key), modes.CTR(self.encrypted_flag_iv))
    decryptor = cipher.decryptor()
    pt = decryptor.update(self.encrypted_flag_data) + decryptor.finalize()
    print('Successfully found private %d, round num %d, pt %r' % (private_key, round_num, pt))
    return pt


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--port', metavar='P', type=int, default=1337, help='challenge #port')
  parser.add_argument(
      '--points', type=str, default='/home/user/attack_points.json', help='attack points json file')
  args = parser.parse_args()

  attacker = Attacker(args.port, args.points)
  attacker.online_step(2)
  attacker.offline_step()

  return 0


if __name__ == '__main__':
  sys.exit(main())
