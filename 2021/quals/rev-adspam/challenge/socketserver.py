#!/bin/python3
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

import argparse
import base64
import json
import logging
import select
import socket
import sys

import license_checker

from Cryptodome.Cipher import AES

HOST = ''
PORT = 1337

DATA_BUFFER = 4096

AES_KEY = b'eaW~IFhnvlIoneLl'

LICENSE_NAME = b'1337_hacker'
LICENSE_NUMBER =  b'798b7dd4-d171-11eb-5149-1fa59603ced5'

CMD_ERROR = -1
CMD_DO_NOTHING = 0
CMD_SHOW_NOTIFICATION = 1
CMD_OPEN_URL = 2

PARAM_CMD = 'cmd'
PARAM_MSG = 'message'
PARAM_DATA = 'data'

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)


def trim_padding(byte_array):
  padding_len = byte_array[-1]
  if padding_len < 16:
    return byte_array[:-padding_len]
  return byte_array

def add_padding(byte_array):
  if len(byte_array) % 16 == 0:
    return byte_array
  padding_len = 16 - len(byte_array) % 16
  logging.debug('padding_len = %d' % padding_len)
  return byte_array + bytes([padding_len] * padding_len)

def compose_ok_packet(cmd, data):
  return {PARAM_CMD: cmd, PARAM_DATA: data}

def compose_error_packet(message):
  return {PARAM_CMD: CMD_ERROR, PARAM_DATA: message}


class Server(object):
  def __init__(self, flag_path):
    self.cipher = AES.new(AES_KEY, AES.MODE_ECB)
    self.checker = license_checker.LicenseChecker(LICENSE_NAME, LICENSE_NUMBER, 0)
    self.flag = open(flag_path, 'r').read()

  def serve(self):
    data = input()
    logging.debug('Data received:\n%s' % data)
    response = self.process_request(data)
    print(response.decode('utf-8'))

  def process_request(self, data):
    response = compose_ok_packet(CMD_DO_NOTHING, '')
    # response = compose_ok_packet(CMD_OPEN_URL, 'https://www.youtube.com/watch?v=dQw4w9WgXcQ')
    # response = compose_ok_packet(
    #      CMD_SHOW_NOTIFICATION, 'Never gonna give you up! Never gonna let you down!')
    logging.info('Received %d bytes' % len(data))
    if len(data) == 0:
      response = compose_error_packet('Received empty request.')
    else:
      try:
        data = trim_padding(self.cipher.decrypt(base64.b64decode(data)))
        packet = json.loads(data)
        license_ = '\n'.join(packet['license'].split('::'))
        res, admin = self.checker.validate(license_.encode('utf-8'))
        if not res:
          response = compose_error_packet(
              'Bad license. Please check the license on the back of the CD box')
        else:
          if admin != 0:
            response = compose_ok_packet(CMD_SHOW_NOTIFICATION, self.flag)
      except Exception as e:
        response = compose_error_packet(str(e))

    response_bytes = add_padding(json.dumps(response).encode('utf-8'))
    logging.debug(response_bytes)
    return base64.b64encode(self.cipher.encrypt(response_bytes))


if __name__ == '__main__':
  parser = argparse.ArgumentParser(
      description='gCTF-2021 rev-adspam server.')
  parser.add_argument('--local', action='store_true', help='Run locally (not in container).')
  args = parser.parse_args()

  if not args.local:
    sys.path.insert(0, "/home/user/")

  server = Server('flag' if args.local else '/home/user/flag')
  try:
    server.serve()
  except KeyboardInterrupt:
    exit()
