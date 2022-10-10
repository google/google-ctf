#!/usr/bin/python3.9

# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import enum
import gmpy2
import hashlib
import hmac
import msgs_pb2 
import os
import time
import typing

debug = True  # We can set it to False when in production.
flag = open('flag.txt', 'rb').read().strip()

class DataType(enum.Enum):
  RSA_ENC = 1
  RSA_SIG = 2

version = "My crypto protocol v0.0.1"
enc_oid = ('For this encryption oid I am not sure, but I would guess something '
           'in between 1.2.840.113549.2.7 and 1.2.840.113549.1.1.5 plus nonce '
           ':).')
sig_oid = ('For this signing oid I am not sure, but I would guess something '
           'in between 1.2.840.113549.2.7 and 1.2.840.113549.1.1.5 plus nonce '
           ':).')
enc_algorithm = ('For this encryption algorithm I am not sure, but I would '
                 'guess something in between hmacWithSHA1 and '
                 'sha1WithRSAEncryption plus nonce :).')
sig_algorithm = ('For this signing algorithm I am not sure, but I would guess '
                 'something in between hmacWithSHA1 and '
                 'sha1-with-rsa-signature plus nonce :).')

def pad(data_to_pad: bytes, block_size: int) -> bytes:
    #Apply ISO/IEC 7816-4 padding.
    padding_len = block_size - len(data_to_pad) % block_size
    padding = b'\x80' + b'\x00'*(padding_len - 1)
    return data_to_pad + padding

def unpad(padded_data: bytes, block_size: int) -> bytes:
    #Remove ISO/IEC 7816-4 padding.
    pdata_len = len(padded_data)
    padding_len = pdata_len - padded_data.rfind(b'\x80')
    return padded_data[:-padding_len]

def bytes2int(bytes_val: bytes) -> int:
  return int.from_bytes(bytes_val, 'big')

def int2bytes(int_val: int) -> bytes:
  int_val = int(int_val)
  return int_val.to_bytes((int_val.bit_length() + 7) // 8, 'big')


class RSA:

  def __init__(self):
    self.e = 65537
    self.p = gmpy2.next_prime(bytes2int(os.urandom(256)) | 2**2047 | 2**2046)
    self.q = gmpy2.next_prime(bytes2int(os.urandom(256)) | 2**2047 | 2**2046)
    self.dp = gmpy2.invert(self.e, self.p-1)
    self.dq = gmpy2.invert(self.e, self.q-1)
    self.qInv = gmpy2.invert(self.q, self.p)
    self.n = self.p*self.q
    self.bl = self.n.bit_length()//8

  def parse(self, msg: bytes, hmac_key: bytes, data_type: DataType) -> int:
    if data_type == DataType.RSA_ENC:
      data = msgs_pb2.RSAEncryptionData()
      data.plaintext = msg
      data.oid = enc_oid
      data.algorithm_name = enc_algorithm
    elif data_type == DataType.RSA_SIG:
      data = msgs_pb2.RSASignatureData()
      data.oid = sig_oid
      data.algorithm_name = sig_algorithm
    else:
      raise ValueError('Unknown Data Type.')
    data.version = version
    data.hmac_key = hmac_key
    data.nonce = hmac.digest(hmac_key, int2bytes(time.time()), hashlib.sha1)
    data.digest_message = hmac.digest(hmac_key, msg, hashlib.sha1)
    m = bytes2int(pad(data.SerializeToString(), self.bl))
    if not m < self.n:
      raise ValueError('Message is too long.')
    return m

  def unparse(self, m: int,
              data_type: DataType) -> typing.Union[msgs_pb2.RSAEncryptionData,
                                                   msgs_pb2.RSAEncryptionData]:
    if data_type == DataType.RSA_ENC:
      data = msgs_pb2.RSAEncryptionData()
    elif data_type == DataType.RSA_SIG:
      data = msgs_pb2.RSASignatureData()
    else:
      raise ValueError('Unknown Data Type.')
    data.ParseFromString(unpad(int2bytes(m), self.bl))
    return data

  def encrypt(self, msg: bytes, hmac_key: bytes) -> int:
    return pow(self.parse(msg, hmac_key, DataType.RSA_ENC), self.e, self.n)

  def decrypt(self, enc: int) -> bytes:
    mp = pow(enc, self.dp, self.p)
    mq = pow(enc, self.dq, self.q)
    h = self.qInv*(mp - mq) % self.p
    m = mq + h*self.q
    data = self.unparse(m, DataType.RSA_ENC)
    digest_message = hmac.digest(data.hmac_key,
                                 data.plaintext,
                                 hashlib.sha1)
    if digest_message != data.digest_message:
      raise ValueError('Can\'t decrypt. Integrity check failed.')
    return data.plaintext

  def sign(self, msg: bytes, hmac_key: bytes) -> int:
    sp = pow(self.parse(msg, hmac_key, DataType.RSA_SIG), self.dp, self.p)
    sq = pow(self.parse(msg, hmac_key, DataType.RSA_SIG), self.dq, self.q)
    h = self.qInv*(sp - sq) % self.p
    s = sq + h*self.q
    return s

  def verify(self, msg: bytes, sig: int) -> bool:
    m = pow(sig, self.e, self.n)
    data = self.unparse(m, DataType.RSA_SIG)
    digest_message = hmac.digest(data.hmac_key, msg, hashlib.sha1)
    return digest_message == data.digest_message

def menu() -> int:
  print("")
  print("[1] Get Public key")
  print("[2] Get Encrypted flag")
  print("[3] Decrypt flag")
  print("[4] Get signed flag")
  print("[5] Verify signed flag")
  print("[6] Exit")
  op = int(input(">>> "))
  return op
 
def operation_loop(rsa):
  while True:
    op = menu()
    if op == 1:
      print('e =', hex(rsa.e))
      print('n =', hex(rsa.n))
    elif op == 2:
      hmac_key = os.urandom(16)
      enc = rsa.encrypt(flag, hmac_key)
      print('enc =', hex(enc))
      if debug:
        assert rsa.decrypt(enc) == flag
    elif op == 3:
      enc = int(input("enc (hex)? "), 16)
      try:
        res = rsa.decrypt(enc)
      except:
        res = None
      if res == flag:
        print("Flag decrypted with success :-)")
      else:
        print("Something went wrong. Incorrect ciphertext?")
    elif op == 4:
      hmac_key = os.urandom(16)
      sig = rsa.sign(flag, hmac_key)
      print('sig =', hex(sig))
      if debug:
        assert rsa.verify(flag, sig)
    elif op == 5:
      sig = int(input("sig (hex)? "), 16)
      try:
        res = rsa.verify(flag, sig)
      except:
        res = None
      if res:
        print("Signed flag verified with success :-)")
      else:
        print("Something went wrong. Incorrect signature?")
    elif op == 6:
      print("Bye!")
      break

if __name__ == "__main__":
  print("\nWelcome to my Crypto box. Tell me what operation you want.")
  while True:
    rsa = RSA()
    try:
      operation_loop(rsa)
      break
    except:
      pass
