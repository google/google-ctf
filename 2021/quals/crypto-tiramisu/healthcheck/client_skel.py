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

import argparse
import pwnlib
import challenge_pb2
import struct
import sys

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec

CHANNEL_CIPHER_KDF_INFO  = b"Channel Cipher v1.0"
CHANNEL_MAC_KDF_INFO = b"Channel MAC v1.0"

IV = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'

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

def handle_pow(tube):
  raise NotImplemented()

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
  assert(c.name == 'secp224r1')
  return challenge_pb2.EcdhKey.CurveID.SECP224R1

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

def run_session(port):
  tube = pwnlib.tubes.remote.remote('127.0.0.1', port)
  print(tube.recvuntil('== proof-of-work: '))
  if tube.recvline().startswith(b'enabled'):
      handle_pow()

  server_hello = read_message(tube, challenge_pb2.ServerHello)
  server_key = proto2key(server_hello.key)
  print(server_hello)

  private_key = ec.generate_private_key(ec.SECP224R1())
  client_hello = challenge_pb2.ClientHello()
  client_hello.key.CopyFrom(key2proto(private_key.public_key()))
  print(client_hello)

  write_message(tube, client_hello)

  shared_key = private_key.exchange(ec.ECDH(), server_key)
  print(shared_key)

  channel = AuthCipher(shared_key, CHANNEL_CIPHER_KDF_INFO, CHANNEL_MAC_KDF_INFO)
  msg = challenge_pb2.SessionMessage()
  msg.encrypted_data.CopyFrom(channel.encrypt(IV, b'hello'))
  write_message(tube, msg)
  print('msg:', msg)

  reply = read_message(tube, challenge_pb2.SessionMessage)
  print('reply:', reply)

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--port', metavar='P', type=int, default=1337, help='challenge #port')
  args = parser.parse_args()

  run_session(args.port)

  return 0


if __name__ == '__main__':
  sys.exit(main())
