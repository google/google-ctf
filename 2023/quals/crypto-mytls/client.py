# Copyright 2023 Google LLC
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

import pwnlib.tubes

import binascii
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from secrets import token_hex
import hashlib
import sys


def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))


def encrypt(message, iv, key):
  cipher = Cipher(
      algorithms.AES(key),
      modes.CBC(binascii.unhexlify(iv)))
  encryptor = cipher.encryptor()
  if isinstance(message, str):
    message = message.encode('utf-8')
  payload = encryptor.update(
      message + b'\x00' * (16 - len(message) % 16)) + encryptor.finalize()
  return binascii.hexlify(payload)


def decrypt(payload, iv, key):
  cipher = Cipher(
      algorithms.AES(key),
      modes.CBC(binascii.unhexlify(iv)))
  decryptor = cipher.decryptor()
  payload = binascii.unhexlify(payload)
  res = decryptor.update(payload)
  return res.strip(b'\x00')

key_path = '../../app/server-ecdhkey.pem'
known = b''
key_length = 241 - len(known)

while True:
  r = pwnlib.tubes.remote.remote(
      sys.argv[3] if len(sys.argv) > 3 else '127.0.0.1',
      sys.argv[4] if len(sys.argv) > 4 else 1337)
  r.recvuntil(b'== proof-of-work: ')
  if r.recvline().startswith(b'enabled'):
      handle_pow(r)
  #r = pwnlib.tubes.process.process('./challenge/server.py')

  # Getting the CA cert.
  with open('challenge/ca-crt.pem', 'rb') as ca_file:
    ca = x509.load_pem_x509_certificate(ca_file.read())
  # Getting the client cert.
  with open(sys.argv[1], 'rb') as client_cert_file:
    client_cert_bytes = client_cert_file.read()
  client_cert = x509.load_pem_x509_certificate(client_cert_bytes)
  # Checking the client key, just to be sure.
  ca.public_key().verify(
      client_cert.signature,
      client_cert.tbs_certificate_bytes,
      padding.PKCS1v15(),
      client_cert.signature_hash_algorithm)
  # Getting the client private key.
  with open(sys.argv[2], 'rb') as client_key_file:
    client_key = serialization.load_pem_private_key(client_key_file.read(),
                                                    None, default_backend())

  server_cert_bytes = r.recvuntil(b'-----END CERTIFICATE-----')
  server_cert = x509.load_pem_x509_certificate(server_cert_bytes)

  r.recvuntil(b'Please provide the client certificate in PEM format:\n')
  r.sendline(client_cert_bytes)

  client_ephemeral_random = token_hex(16)
  r.recvuntil(b'Please provide the ephemeral client random:\n')
  r.sendline(client_ephemeral_random.encode('utf-8'))

  r.recvuntil(b'Please provide the ephemeral client key:')
  client_ephemeral_key = ec.generate_private_key(ec.SECP256R1(),
                                                 default_backend())
  client_ephemeral_public_key = client_ephemeral_key.public_key()
  r.sendline(client_ephemeral_public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo))

  r.recvuntil(b'Server ephemeral random:\n')
  server_ephemeral_random = r.recvuntil(b'\n').strip()

  r.recvuntil(b'Server ephemeral key:\n')
  server_ephemeral_key_bytes = r.recvuntil(b'-----END PUBLIC KEY-----\n')
  server_ephemeral_public_key = serialization.load_pem_public_key(
      server_ephemeral_key_bytes)

  client_ephemeral_secret = client_ephemeral_key.exchange(
      ec.ECDH(), server_ephemeral_public_key)
  if '--kci' in sys.argv:
    client_secret = client_key.exchange(ec.ECDH(), client_cert.public_key())
  else:
    client_secret = client_key.exchange(ec.ECDH(), server_cert.public_key())
  derived_key = HKDF(algorithm=hashes.SHA256(),
                     length=32,
                     salt=b'SaltyMcSaltFace',
                     info=b'mytls').derive(
                         client_ephemeral_secret +
                         client_secret +
                         client_ephemeral_random.encode('utf-8') +
                         server_ephemeral_random)

  r.recvuntil(b'Please provide the client HMAC:')
  client_hmac = hmac.HMAC(derived_key, hashes.SHA256())
  client_hmac.update(b'client myTLS successful!')
  r.sendline(binascii.hexlify(client_hmac.finalize()))

  r.recvuntil(b'Server HMAC:\n')
  server_hmac_bytes = r.recvuntil(b'\n').strip()
  server_hmac = hmac.HMAC(derived_key, hashes.SHA256())
  server_hmac.update(b'server myTLS successful!')
  server_hmac.verify(binascii.unhexlify(server_hmac_bytes))

  print('[+] myTLS negotiation successful')

  payload_hex = r.recvuntil(b'\n').strip()
  print(decrypt(payload_hex, server_ephemeral_random, derived_key))

  # selecting slot
  payload_hex = r.recvuntil(b'\n').strip()
  #print(decrypt(payload_hex, server_ephemeral_random, derived_key))
  msg = encrypt(key_path, server_ephemeral_random, derived_key)
  r.sendline(msg)

  # partial overwrite
  overwrite_payload = b'A'*(key_length-1-len(known))
  print('Payload:', repr(overwrite_payload))
  payload_hex = r.recvuntil(b'\n').strip()
  #print(decrypt(payload_hex, server_ephemeral_random, derived_key))
  msg = encrypt(overwrite_payload, server_ephemeral_random,
                derived_key)
  r.sendline(msg)

  payload_hex = r.recvuntil(b'\n').strip()
  #print(decrypt(payload_hex, server_ephemeral_random, derived_key))

  # selecting slot
  payload_hex = r.recvuntil(b'\n').strip()
  #print(decrypt(payload_hex, server_ephemeral_random, derived_key))
  msg = encrypt(key_path, server_ephemeral_random, derived_key)
  r.sendline(msg)

  # useless overwrite
  payload_hex = r.recvuntil(b'\n').strip()
  #print(decrypt(payload_hex, server_ephemeral_random, derived_key))
  msg = encrypt('A', server_ephemeral_random, derived_key)
  r.sendline(msg)

  # Get hash
  payload_hex = r.recvuntil(b'\n').strip()
  got_hash = decrypt(payload_hex, server_ephemeral_random,
                     derived_key).split(b'reference: ')[1].decode('utf-8')
  print('Got hash:', repr(got_hash))
  found = False
  for i in range(256):
    h = hashlib.new('sha256')
    h.update(overwrite_payload + chr(i).encode('utf-8') + known)
    curr_hash = h.hexdigest()
    if curr_hash == got_hash:
      found = True
      print('FOUND!!', repr(chr(i)))
      known = chr(i).encode('utf-8') + known
      print('Leak: ' + repr(known))
      break
  if not found:
    print('FAIL')
    exit(1)
  r.close()
