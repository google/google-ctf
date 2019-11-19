#! /usr/bin/python3

# Copyright 2019 Google LLC
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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import vmac64
"""
Return of the (V)MAC:
================================================================================
"""

MSG_SECRET = open('data/secret.txt', 'rb').read()
FLAG = open('data/flag.txt', 'r').read()

class SecretVerifier:

  def __init__(self):
    key = self.key_exchange()
    self.vmac = vmac64.Vmac64(key)

  def key_exchange(self):
    server_sk = ec.generate_private_key(ec.SECP384R1(), default_backend())
    server_der = server_sk.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    print('Server Public Key (hex): \n{0}'.format(bytes.hex(server_der)))

    client_pk = bytes.fromhex(input('Send your public key (hex): \n'))
    client_der = serialization.load_der_public_key(client_pk, default_backend())
    shared_key = server_sk.exchange(ec.ECDH(), client_der)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'handshake data',
        backend=default_backend()).derive(shared_key)
    return derived_key

  def verify(self, nonce, tag, msg_pub):
    return self.vmac.tag(msg_pub + MSG_SECRET, nonce) == tag

if __name__ == '__main__':
  secret_verifier = SecretVerifier()
  data = bytes.fromhex(input('Please, prove you know stuffs: '))
  NONCE, TAG, MSG_PUBLIC = data[:8], data[8:16], data[16:24]
  if secret_verifier.verify(NONCE, TAG, MSG_PUBLIC):
    print('\n\nYou got the flag!\n{0}'.format(FLAG))
  else:
    print('\n\nLooks like you don\'t know the secret...')
