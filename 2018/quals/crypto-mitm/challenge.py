#!/usr/bin/env python3
"""
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from binascii import hexlify
from binascii import unhexlify
import logging
import sys
import os

from curve25519 import Private, Public
import nacl.secret
import hmac
import hashlib

logger = logging.getLogger('challenge')


def ReadLine(reader):
  data = b''
  while not data.endswith(b'\n'):
    cur = reader.read(1)
    data += cur
    if cur == b'':
      return data
  return data[:-1]


def WriteLine(writer, msg):
  writer.write(msg + b'\n')
  writer.flush()


def ReadBin(reader):
  return unhexlify(ReadLine(reader))


def WriteBin(writer, data):
  WriteLine(writer, hexlify(data))


def ComputeProof(key, data):
  return hmac.new(key, data, digestmod=hashlib.sha256).digest()


def VerifyProof(key, data, proof):
  return hmac.compare_digest(ComputeProof(key, data), proof)


def Handshake(password, reader, writer):
  myPrivateKey = Private()
  myNonce = os.urandom(32)

  WriteBin(writer, myPrivateKey.get_public().serialize())
  WriteBin(writer, myNonce)

  theirPublicKey = ReadBin(reader)
  theirNonce = ReadBin(reader)

  if myNonce == theirNonce:
    return None
  if theirPublicKey in (b'\x00'*32, b'\x01' + (b'\x00' * 31)):
    return None

  theirPublicKey = Public(theirPublicKey)

  sharedKey = myPrivateKey.get_shared_key(theirPublicKey)
  myProof = ComputeProof(sharedKey, theirNonce + password)

  WriteBin(writer, myProof)
  theirProof = ReadBin(reader)

  if not VerifyProof(sharedKey, myNonce + password, theirProof):
    return None

  return sharedKey


def Server(password, flag, reader, writer):
  sharedKey = Handshake(password, reader, writer)
  if sharedKey is None:
    WriteLine(writer, b'Error: nope.')
    return 1

  mySecretBox = nacl.secret.SecretBox(sharedKey)
  WriteBin(writer, mySecretBox.encrypt(b"AUTHENTICATED"))

  while 1:
    cmd = mySecretBox.decrypt(ReadBin(reader))
    if cmd == b'help':
      rsp = b'help|exit|whoami|getflag'
    elif cmd == b'exit':
      return 0
    elif cmd == b'whoami':
      rsp = b'root'
    elif cmd == b'getflag':
      rsp = flag
    else:
      return 1
    WriteBin(writer, mySecretBox.encrypt(rsp))


def Client(password, reader, writer):
  sharedKey = Handshake(password, reader, writer)
  if sharedKey is None:
    WriteLine(writer, b'Error: nope.')
    return 1

  mySecretBox = nacl.secret.SecretBox(sharedKey)
  line = mySecretBox.decrypt(ReadBin(reader))
  if line != b"AUTHENTICATED":
    WriteLine(writer, b'Error: nope.')
    return 1

  WriteBin(writer, mySecretBox.encrypt(b"whoami"))
  line = mySecretBox.decrypt(ReadBin(reader))

  if line != b'root':
    return 1

  WriteBin(writer, mySecretBox.encrypt(b"exit"))
  return 0


def Challenge(password, flag, reader, writer):
  try:
    server_or_client = ReadLine(reader)
    is_server = server_or_client[0] in b'sS'
    is_client = server_or_client[0] in b'cC'

    if is_server:
      return Server(password, flag, reader, writer)
    elif is_client:
      return Client(password, reader, writer)
    else:
      WriteLine(writer, b'Error: Select if you want to speak to the (s)erver or (c)lient.')
      return 1
  except Exception as e:
    WriteLine(writer, b'Error')
    return 1


def main():
  logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
  password, flag = map(lambda f: open(f, 'rb').read().strip(), sys.argv[1:3])
  assert(flag.startswith(b'CTF{') and flag.endswith(b'}'))
  return Challenge(password, flag, sys.stdin.buffer, sys.stdout.buffer)


if __name__ == '__main__':
  sys.exit(main())
