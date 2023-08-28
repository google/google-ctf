#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
r.recvuntil(b'== proof-of-work: ')
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

# Getting the CA cert.
with open('/home/user/ca-crt.pem', 'rb') as ca_file:
  ca = x509.load_pem_x509_certificate(ca_file.read())
# Getting the admin client cert.
with open('/home/user/admin-ecdhcert.pem', 'rb') as client_cert_file:
  client_cert_bytes = client_cert_file.read()
client_cert = x509.load_pem_x509_certificate(client_cert_bytes)
# Checking the client key, just to be sure.
ca.public_key().verify(
    client_cert.signature,
    client_cert.tbs_certificate_bytes,
    padding.PKCS1v15(),
    client_cert.signature_hash_algorithm)
# Getting the server private key.
with open('/home/user/server-ecdhkey.pem', 'rb') as server_key_file:
  server_key = serialization.load_pem_private_key(server_key_file.read(),
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
server_secret = server_key.exchange(ec.ECDH(), client_cert.public_key())
derived_key = HKDF(algorithm=hashes.SHA256(),
                   length=32,
                   salt=b'SaltyMcSaltFace',
                   info=b'mytls').derive(
                       client_ephemeral_secret +
                       server_secret +
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

payload_hex = r.recvuntil(b'\n').strip()
cipher = Cipher(
    algorithms.AES(derived_key),
    modes.CBC(binascii.unhexlify(server_ephemeral_random)))
decryptor = cipher.decryptor()
plaintext = decryptor.update(binascii.unhexlify(payload_hex))

if b'CTF{' not in plaintext:
  exit(1)

exit(0)
