#!/usr/bin/python
#
# Copyright 2018 Google LLC
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

import json, tempfile, subprocess, os

with open('metadata.json') as f:
    data = json.load(f)
flag = data['challenge']['flag'].strip()

print "Generating challenge for flag {}...".format(flag)

subprocess.check_output('cd challenge && cargo build --release && cp target/release/encrypt . && rm -rf target Cargo.lock', shell = True)
key = subprocess.check_output('cd solver && cargo run --bin keygen 2>/dev/null', shell = True).strip()

with tempfile.NamedTemporaryFile() as f:
  f.write(flag)
  f.write('\n')
  f.flush()

  subprocess.check_output(['./challenge/encrypt', key, f.name])
  with open(f.name + '.enc') as fenc:
    data = fenc.read()
with open('./challenge/flag.txt.enc', 'w') as f:
  f.write(data)
subprocess.check_output(['tar', 'jcf', 'attachments/challenge.tar.bz2', 'challenge'])
