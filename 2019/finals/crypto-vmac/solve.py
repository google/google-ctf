#! /usr/bin/python2

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
# limitations under the License

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pwn import *

p = process("challenge.py")

client_sk = ec.generate_private_key(ec.SECP384R1(), default_backend())
client_pk = client_sk.public_key()
client_der = client_pk.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

res = p.recvuntil("Send your public key (hex):")
server_der = res.split("\n")[1].decode("hex")

server_pk = serialization.load_der_public_key(server_der, default_backend())
shared_key = client_sk.exchange(ec.ECDH(), server_pk)
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=16,
    salt=None,
    info=b"handshake data",
    backend=default_backend()).derive(shared_key)

p.sendline(client_der.encode('hex'))
res = p.recvuntil("Please, prove you know stuffs: ")
msg = process(["collide.py", derived_key.encode("hex")]).recvall().split("\n")[1]
p.sendline(msg)
flag = p.recvall()
print(flag)
