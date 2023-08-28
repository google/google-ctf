#!/usr/bin/env python3

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
import hashlib
import os
from secrets import token_hex


with open('/app/flag.txt') as f:
  _FLAG = f.read()
os.unlink('/app/flag.txt')

def print_encrypted(message, iv, key):
  cipher = Cipher(
      algorithms.AES(key),
      modes.CBC(binascii.unhexlify(iv)))
  encryptor = cipher.encryptor()
  message = message.encode('utf-8')
  payload = encryptor.update(
      message + b'\x00' * (16 - len(message) % 16)) + encryptor.finalize()
  print(binascii.hexlify(payload).decode('utf-8'))


def input_encrypted(iv, key):
  cipher = Cipher(
      algorithms.AES(key),
      modes.CBC(binascii.unhexlify(iv)))
  decryptor = cipher.decryptor()
  payload = input()
  payload = binascii.unhexlify(payload)
  res = decryptor.update(payload)
  return res.strip(b'\x00')


def main():
  # Getting the CA cert.
  with open('ca-crt.pem', 'rb') as ca_file:
    ca = x509.load_pem_x509_certificate(ca_file.read())
  # Getting the server cert.
  with open('server-ecdhcert.pem', 'rb') as server_cert_file:
    server_cert_content = server_cert_file.read()
    server_cert = x509.load_pem_x509_certificate(server_cert_content)
  print(server_cert_content.decode('utf-8'))
  # Checking the server key, just to be sure.
  ca.public_key().verify(
      server_cert.signature,
      server_cert.tbs_certificate_bytes,
      padding.PKCS1v15(),
      server_cert.signature_hash_algorithm)
  # Getting the server private key.
  with open('server-ecdhkey.pem', 'rb') as server_key_file:
    server_key = serialization.load_pem_private_key(server_key_file.read(),
                                                    None, default_backend())
  # Getting the client cert.
  print('Please provide the client certificate in PEM format:')
  client_cert_content = ''
  client_cert_line = None
  while client_cert_line != '':
    client_cert_line = input()
    client_cert_content += client_cert_line + '\n'
  client_cert = x509.load_pem_x509_certificate(
      client_cert_content.encode('utf-8'))
  # Checking the client key, this is important. We don't want fakes here!
  ca.public_key().verify(
      client_cert.signature,
      client_cert.tbs_certificate_bytes,
      padding.PKCS1v15(),
      client_cert.signature_hash_algorithm)

  # Get ephemeral client random
  print('Please provide the ephemeral client random:')
  client_ephemeral_random = input()
  if len(client_ephemeral_random) != 32:
    print('ERROR: invalid client random length')
    exit(1)

  # Get ephemeral client key
  print('Please provide the ephemeral client key:')
  client_ephemeral_key_content = ''
  client_ephemeral_key_line = None
  while client_ephemeral_key_line != '':
    client_ephemeral_key_line = input()
    client_ephemeral_key_content += client_ephemeral_key_line + '\n'
  client_ephemeral_public_key = serialization.load_pem_public_key(
      client_ephemeral_key_content.encode('utf-8'))

  # Generate ephemeral server random
  server_ephemeral_random = token_hex(16)
  print('Server ephemeral random:')
  print(server_ephemeral_random)

  # Generate ephemeral server key
  server_ephemeral_key = ec.generate_private_key(ec.SECP256R1(),
                                                 default_backend())
  server_ephemeral_public_key = server_ephemeral_key.public_key()
  print('Server ephemeral key:')
  print(server_ephemeral_public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8'))

  server_ephemeral_secret = server_ephemeral_key.exchange(
      ec.ECDH(), client_ephemeral_public_key)
  server_secret = server_key.exchange(ec.ECDH(), client_cert.public_key())
  derived_key = HKDF(algorithm=hashes.SHA256(),
                     length=32,
                     salt=b'SaltyMcSaltFace',
                     info=b'mytls').derive(
                         server_ephemeral_secret +
                         server_secret +
                         client_ephemeral_random.encode('utf-8') +
                         server_ephemeral_random.encode('utf-8'))

  print('Please provide the client HMAC:')
  client_hmac_content = input()
  client_hmac = hmac.HMAC(derived_key, hashes.SHA256())
  client_hmac.update(b'client myTLS successful!')
  client_hmac.verify(binascii.unhexlify(client_hmac_content))

  server_hmac = hmac.HMAC(derived_key, hashes.SHA256())
  server_hmac.update(b'server myTLS successful!')
  print('Server HMAC:')
  print(binascii.hexlify(server_hmac.finalize()).decode('utf-8'))

  message = 'Hello guest!'
  if 'CN=admin.mytls' in client_cert.subject.rfc4514_string():
      message = 'Hello admin! ' + _FLAG

  print_encrypted(message, server_ephemeral_random, derived_key)
  while True:
    print_encrypted(
        'Welcome to our write-only file storage!\n\n'
        'Select the storage slot [0-9]:',
        server_ephemeral_random, derived_key)
    storage_slot = input_encrypted(server_ephemeral_random, derived_key)
    path = os.path.join('/tmp/storage/', storage_slot.decode('utf-8'))
    print_encrypted('Gimme your secrets:', server_ephemeral_random,
                    derived_key)
    secret = input_encrypted(server_ephemeral_random, derived_key)
    with open(path, 'rb+') as f:
      h = hashlib.new('sha256')
      h.update(f.read())
      prev_hash = h.hexdigest()
      f.seek(0)
      f.write(secret)
      print_encrypted('Saved! Previous secret reference: ' + prev_hash,
                      server_ephemeral_random, derived_key)

if __name__ == '__main__':
  main()
