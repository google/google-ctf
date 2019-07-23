#!/usr/bin/python

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

import logging
import os
import nameko
import subprocess
import json
from nameko.web.handlers import HttpRequestHandler
from nameko.timer import timer
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
    address = os.environ.get('ADDRESS', '127.0.0.1')
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
def healthcheck_challenge(address, port):
  # Read the flag from the config, but only once.
  if not hasattr(healthcheck_challenge, 'flag_loaded'):
    with open('metadata.json') as f:
      metadata = json.load(f)
    healthcheck_challenge.flag = bytes(metadata['challenge']['flag'], 'utf-8')
    healthcheck_challenge.flag_loaded = True

  # Run the exploit and check if it's output had the flag.
  PLACEHOLDER_FLAG = b'On the real server the flag is loaded here'
  p = subprocess.Popen(
      ['go', 'run', 'exploit.go', '--remote', '%s:%i' % (address, port)],
      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  # NOTE: This is slow, but that's not a problem, as nameko will not start
  # other instances of the timer callback until this is over AND the HTTP
  # server is responsive while this is running.
  (stdout, stderr) = p.communicate(timeout=60)
  for line in stderr.splitlines():
    if b'Flag:' not in line:
      continue

    _, flag_candidate = line.split(b'Flag:', 1)
    if (healthcheck_challenge.flag in flag_candidate or
        PLACEHOLDER_FLAG in flag_candidate):
      return True

  return False
