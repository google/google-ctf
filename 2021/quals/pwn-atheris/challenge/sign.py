# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Author: Ian Eldred Pudney

import sys
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519

def encode_sig(sig):
  b64 = base64.encodebytes(sig).decode("utf-8")
  b64 = b64.replace("/", "_")
  b64 = b64.replace("\n", "")
  b64 = b64.replace("=", "")  # All sigs are the same length
  return b64

if not sys.argv[1].endswith(".autorun.py"):
  raise RuntimeError(f"Filename must end with .autorun.py; got autorun {sys.argv[1]}")

with open("private_key", "rb") as f:
  private_key = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
with open("public_key", "rb") as f:
  public_key = ed25519.Ed25519PublicKey.from_public_bytes(f.read())

with open(sys.argv[1], "rb") as f:
  data = f.read()

sig = private_key.sign(data)
public_key.verify(sig, data)

new_filename = sys.argv[1][0:-11] + "." + encode_sig(sig) + ".autorun.py"
with open(new_filename, "wb") as f:
  f.write(data)


