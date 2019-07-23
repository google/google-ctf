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

import base64
import os
import random
import time
import string
import shutil
import socket
import subprocess
import tarfile
import tempfile
import thread
import threading
import signal
import sys
import StringIO
import hashlib

# tmpfile = "/tmp/1234"

def _rand_str():
    return ''.join(random.choice(string.lowercase) for _ in range(10))

TIMEOUT=300

FLAG = "CTF{wh0-n33ds-multiarch-an1way}"
STAGE_ELF_FLAG = "Pull_that_lever1"
MESSAGE = (
'Give me a bios image that I can load into qemu that will send '
'"%s" to 169.254.169.254:80 over tcp. The server can be delayed a bit, '
'so your payload should retry connecting. '
'And by the way, it has to work both in x86_64 and on a '
'qemu arm virt-2.8 machine, all in under %d seconds')%(STAGE_ELF_FLAG, TIMEOUT)

def _launch_cmd(cmd):
    try:
      subprocess.check_output(" ".join(cmd),
                              shell=True,
                              stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
      print "Process failed with output: %s"%e.output

def _launch_qemu_x86(port, tmpfile, fn=_launch_cmd):
  return fn([
  '/usr/bin/qemu-system-x86_64',
  '-nographic',
  '-net',
  'nic',
  '-net',
  '"user,restrict=on,net=169.254.0.0/16,host=169.254.169.253,guestfwd=tcp:169.254.169.254:80-cmd:netcat 127.0.0.1 {}"'.format(port),
  '-bios {}'.format(tmpfile)])

def _launch_qemu_arm(port, tmpfile, fn=_launch_cmd):
  return fn([
  '/usr/bin/qemu-system-arm',
  '-nographic',
  '-machine', 'virt-2.8',
  '-net',
  'nic',
  '-net',
  '"user,restrict=on,net=169.254.0.0/16,host=169.254.169.253,guestfwd=tcp:169.254.169.254:80-cmd:netcat 127.0.0.1 {}"'.format(port),
    '-bios',
    '{}'.format(tmpfile)])

def debug_cmd(args):
  return " ".join(args)

class Handler(object):
  def __enter__(self):
    self._tmpdir = tempfile.mkdtemp()
    self._x86_port = random.randint(10000,20000)
    self._arm_port = random.randint(10000,20000)
    return self

  def __exit__(self, type, value, traceback):
    if hasattr(self, 'container'):
      self.container.kill()
    shutil.rmtree(self._tmpdir)

  def _make_tmpfile(self, contents):
    fpath = os.path.join(self._tmpdir, _rand_str())
    with open(fpath, 'w') as f:
      f.write(contents)
    return fpath

  def _wait_for_confirmation(self, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT/2)
    s.bind(('localhost', port))
    s.listen(1)
    start = time.time()
    while time.time() - start < TIMEOUT/2:
      conn, cli_addr = s.accept()
      f = conn.makefile()
      while time.time() - start < TIMEOUT/2:
        if STAGE_ELF_FLAG in f.readline():
          return
    raise ValueError("Timeout")

  def stage_disk(self):
    msg = raw_input("Boot image (base64 encoded, limit 3MiB encoded): ")
    if len(msg) > 1024*1024*3:
      raise ValueError('boot image too large.')
    tmpfile = self._make_tmpfile(base64.b64decode(msg))
    thread.start_new_thread(_launch_qemu_x86, (self._x86_port, tmpfile))
    thread.start_new_thread(_launch_qemu_arm, (self._arm_port, tmpfile))
    print 'Launching servers'
    # Randomize which server goes first.
    if random.random() > 0.5:
      self._wait_for_confirmation(self._x86_port)
      print 'Got x86 lever!'
      self._wait_for_confirmation(self._arm_port)
      print 'Got ARM lever!'
    else:
      self._wait_for_confirmation(self._arm_port)
      print 'Got ARM lever!'
      self._wait_for_confirmation(self._x86_port)
      print 'Got x86 lever!'


def run_challenge(h):
  print MESSAGE
  print
  print "To make your life easier, here are the commands the server will run:"
  print
  print _launch_qemu_arm("$random_port", "$tmpfile", debug_cmd)
  print
  print _launch_qemu_x86("$random_port", "$tmpfile", debug_cmd)
  print
  try:
    h.stage_disk()
    print "Here's your flag: " + FLAG
  except Exception as e:
    print "Error: {}".format(e)

def main():
  with Handler() as h:
    challenge = threading.Thread(target=run_challenge, args=(h,))
    challenge.daemon = True
    challenge.start()

    challenge.join(TIMEOUT)

    if challenge.is_alive():
      print "Timeout! I'm done!"

if __name__ == '__main__':
  res = main()

