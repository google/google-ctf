#!/usr/bin/python3 -u
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
import tempfile
import sys
import subprocess

with tempfile.TemporaryDirectory() as d:
  try:
    num_bytes = int(input('How many bytes is your base64-encoded exploit? '))
    if num_bytes > 2**20:
      print('Too big')
      exit(0)

    print('Give me your exploit as base64!')
    data = base64.b64decode(sys.stdin.buffer.read(num_bytes))

    with open(f'{d}/exploit.html', 'wb') as f:
      f.write(data)

    print('Let\'s go!')

    subprocess.check_call([
      '/usr/bin/qemu-system-x86_64',
      '-enable-kvm',
      '-nographic',
      '-monitor', 'none',
      '-m', '512M',
      '-cpu', 'qemu64,+smep,+smap',
      '-no-reboot',
      '-kernel', './bzImage',
      '-drive', 'file=./rootfs.img,format=raw,if=virtio,readonly',
      '-drive', 'file=./flag,format=raw,if=virtio,readonly',
      '-append', 'console=ttyS0 kaslr kpti=1 root=/dev/vda init=/init panic=1 quiet',
      '-virtfs', f'local,readonly,mount_tag=exploit,security_model=none,path={d}',
    ])
  except:
    print('Bye!')
