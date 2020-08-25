# Copyright 2020 Google LLC
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

import logging
import os

import nameko
from nameko.web.handlers import HttpRequestHandler
from nameko.timer import timer
import socket

logger = logging.getLogger('healthcheck')

http = HttpRequestHandler.decorator

state = {
    'healthy': None
}

class HealthcheckService:
  name = 'healthcheck'


  @http('GET', '/')
  def healthcheck_handler(self, request):
    if state['healthy']:
      return 200, 'healthy\n'
    else:
      return 503, 'unhealthy\n'

  @timer(interval=10)
  def healtcheck(self):
    address = os.environ.get('ADDRESS', '127.0.0.01')
    port = int(os.environ.get('PORT', '1337'))

    retries = 5
    while retries > 0:
      health = False
      try:
        health = healthcheck_challenge(address, port)
      except Exception as e:
        logger.warning('Healthcheck exception: {}'.format(e))
      if health:
        break
      logger.info('Retrying...')
      retries -= 1

    if health != state['healthy']:
      if health:
        logger.info('Challenge became healthy.')
      else:
        logger.info('Challenge became unhealthy.')
    state['healthy'] = health



# Implement your healthchecking here.
# Beware, this framework uses eventlet - third party I/O libraries might not
# work. Also, this is Python3.

def recv_until(s, needle):
  data = b''
  while not data.endswith(needle):
    r = s.recv(1)
    if not r:
      raise StopIteration
    data += r
  return data

def healthcheck_challenge(address, port):
  try:
    sock = socket.create_connection((address, port))
    sock.settimeout(30)
    recv_until(sock, b'[y/N]\n')
    sock.sendall(b'y\n')
    recv_until(sock, b'a token for:\n')
    recv_until(sock, b'hashcash -mb')
    sock.sendall(b'blah-blah-blah\n')
    sock.close()
    return True
  except:
    return False
