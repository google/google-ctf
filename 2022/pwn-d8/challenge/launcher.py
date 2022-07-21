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

import sys
import io
import subprocess

def main():
  reader = io.BufferedReader(sys.stdin.buffer, buffer_size=1)

  print('File size:', flush=True)
  input_size = int(reader.readline())
  if input_size <= 0 or input_size > 65536:
    print('Invalid file size.', flush=True)
    return

  print('File data:', flush=True)
  input_data = reader.read(input_size)
  with open('/tmp/data', 'wb') as f:
    f.write(input_data)

  process = subprocess.Popen(
      ['./challenge', '/tmp/data'],
      stdin=subprocess.DEVNULL,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE)
  outs, errs = process.communicate()
  sys.stdout.buffer.write(outs)
  sys.stdout.buffer.write(errs)
  sys.stdout.flush()


if __name__ == '__main__':
  main()
