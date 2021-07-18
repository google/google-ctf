# Copyright 2021 Google LLC
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

import base64
import json
import logging
import struct

from Cryptodome.PublicKey import RSA


SERVER_KEY = base64.b64decode(
    (
        'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlDWFFJQkFBS0JnUUN3QWI4eDI4YWlSOHJNcU5KNVZRY2dvTCtU'
        'VjBOZVJsVXNaZVUyem5GNnRnbWRTcS9ICm4vMFo1R1JFaEd0MkV6YU8xcjlIaG5FemFSODE2cmpwNVRhSUl1N01jOFFBMkNj'
        'aXFQT1cwaUgrL2tWVU4vcEwKV2JCa1hPdGRIa0xkbCt1b0dDczNSRkt2eEJyQm03UlpzTkF0dk5YcE8zejdVTXpvcUs1TjNR'
        'YkJkd0lEQVFBQgpBb0dBRmZHeHo5cVI4bXUzQ2p0R09xQnlTZ3dndHBNYnNDWmV1akZlR2E0MWtkSWVjc0Q4RjR5SDl2RjEy'
        'dUVUCnNONEdZRnEvOEgvL255Uk5JdURIKzBsN3VkcDNHL0RROXcxY0lOajJXeDhTazRvd0xDYUJ1akhoeklqL2hJWWwKWUhh'
        'aVlHZjdFRFlSdFJSd0owWGRkZE5zWGYzbWo5RWc0UVRvU3Y0UG1MdmhjZ0VDUVFEZ0JnQWpleVNma2RmWQpPbm45ODBqRzJn'
        'ZW9jSGZWRVJqZlVXNkE0ZjVlTnBVQkRvMUtLS2Y4VDZ1T2FPS3NOREJueXdHOTdUeisrY0FRCjQxdzQyVnAzQWtFQXlTRXVF'
        'UWdheHdsVlR1SkhMSXNkOVdKRDdHL0V6aGVQRTVQdWYvNWh0MEMrYkxFUjFVSjIKbjE2eE92dVZFVUsvY2ttcThFMTVwbmcx'
        'dFpIRnc1Q1JBUUpCQUt2bER0QXEya1F5bFV1T096TVlMUnlnQ2NZKwpYa1M0Tkx5T2NGc21qWmJmRE9CZHVSNVJLZXpaZVFy'
        'eUFoUWVpNUhvM0hKT2lrSWZnemV5TFg1VmtTc0NRRE1BCnVmalJzRkNtdWo1TnZUUzdkblppVzgwYUxyTUFZR1RiajVCZmhw'
        'SDgxZzBqL2R5eGhQazIvd1J4QmNVaHd3Q04KVTg2cUp0NGkvNk95ZW83MEd3RUNRUUNDblFIa1VSMjJtekpSNHM2Zzl1c1NB'
        'Z1dmVThnQUxkQTBMLzU1dTlLQQpDM21MTkErall4NXY1UzZOMGI0MHM5NlRUMmJmb3pjcmpVbWl3SVVrbjJjNgotLS0tLUVOR'
        'CBSU0EgUFJJVkFURSBLRVktLS0tLQ=='))

BLOCK_SIZE = 4

class LicenseChecker(object):
  def __init__(self, name, number, admin):
    private_key = RSA.importKey(SERVER_KEY)

    self.n = private_key.n
    self.e = private_key.e
    self.d = private_key.d

    self.name = name
    self.number = number
    self.admin = admin

  def encrypt(self, word):
    x = struct.unpack('>I', word)[0]
    y = pow(x, self.d, self.n)
    return y.to_bytes(128, 'big')

  def decrypt(self, word):
    y = int.from_bytes(word, 'big')
    x = pow(y, self.e, self.n)
    return struct.pack('>I', x)


  def parse_value(self, data):
    if not data:
      raise ValueError('License string is empty.')

    value_len = data[0]
    if len(data[1:]) < value_len:
      raise ValueError(
          'Deserialization error: expected %d bytes, found %d bytes in the license string.' % (
              value_len, len(data[1:])))

    value = data[1:value_len+1]
    return value, data[value_len+1:]

  def deserialize(self, data):
    name, data = self.parse_value(data)
    number, data = self.parse_value(data)
    admin, _ = self.parse_value(data)
    return {'name': name, 'number': number, 'admin': int(admin)}

  def serialize(self):
      res = b''
      for value in [self.name, self.number, str(self.admin).encode('utf-8')]:
        res += struct.pack('<B', len(value))
        res += value
      return res

  def export(self):
    license_string = self.serialize()
    padding_len = BLOCK_SIZE - len(license_string) % BLOCK_SIZE
    license_string += b'\x00' * padding_len
    result = []
    for i in range(0, len(license_string), BLOCK_SIZE):
      word = license_string[i:i+BLOCK_SIZE]
      encrypted = self.encrypt(word)
      result.append( base64.b64encode(encrypted) )
    return b'\n'.join(result)

  def validate(self, data):
    words = data.split(b'\n')
    license_string = b''
    for word in words:
      decrypted = self.decrypt(base64.b64decode(word))
      license_string += decrypted

    values = self.deserialize(license_string)
    logging.debug(values)
    return values['name'] == self.name and values['number'] == self.number, values['admin']
