#!/usr/bin/python3

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

"""Finds the first *.<sig>.autorun.py file in a given ZIP file that's signed with the trusted public key."""

# arguments:
#  - argv[1]: path to zip file

import os
import sys
import zipfile
import turbozipfile
import subprocess
import sys
import base64
import cryptography
from cryptography.hazmat.primitives.asymmetric import ed25519

with open(os.path.join(os.getcwd(), "public_key"), "rb") as f:
  public_key = ed25519.Ed25519PublicKey.from_public_bytes(f.read())

# This is not a cryptography challenge. The expected solution has
# nothing to do with breaking ed25519.
def check_signature(filename, file_bytes):
  b64 = filename.encode("utf-8")[0:-11]
  b64 = b64[-87:]
  b64 += b"=="
  b64 = b64.replace(b"_", b"/")
  sig = base64.decodebytes(b64)
  public_key.verify(sig, file_bytes)

def is_autorun(info):
  if info.is_dir():
    return False
  if not info.filename.endswith(".autorun.py"):
    return False
  return True

def validate_zipfile(info):
  if not info.filename:
    raise RuntimeError(f"Empty filename not allowed: {info.filename}")
  if info.filename[0] == '/':
    raise RuntimeError(f"Relative-to-root filename not allowed: {info.filename}")
  if ".." in info.filename.split("/"):
    raise RuntimeError(f"Directory backtracking in filename not allowed: {info.filename}")
  if "\0" in info.filename:
    raise RuntimeError(f"Null byte in filename not allowed: {info.filename}")
  if info.external_attr & 0x20000000:
    raise RuntimeError(f"Symlink not allowed: {info.filename}")
  disallowed_extras=[0x554e, 0x7075]
  extra = info.extra
  while extra:
    typ = int.from_bytes(extra[0:2], "little")
    if typ in disallowed_extras:
      raise RuntimeError(f"Extra field header {hex(typ)} not allowed: {info.filename}")
    sz = 4 + int.from_bytes(extra[2:4], "little")
    extra = extra[sz:]

def find_valid_autorun(zip_filename):
  with open(zip_filename, "rb") as f:
    z = zipfile.ZipFile(f)
    infos = z.infolist()

    # Validate that this zip file is safe
    for info in infos:
      validate_zipfile(info)

    seen_files = []
    for info in infos:
      if info.filename in seen_files:
        raise RuntimeError(f"Multiple files with the same filename not allowed: {info.filename}")
      seen_files.append(info.filename)

    for info in infos:
      if not is_autorun(info):
        continue

      with z.open(info, "r") as g:
        data = g.read()
        try:
          check_signature(info.filename, data)
          return info.filename
        except cryptography.exceptions.InvalidSignature:
          # Not an error - otherwise, files that happen to end in .autorun.py
          # would break, even if those are just user-provided files.
          sys.stderr.write(f"WARNING: Signature verification failed: {info.filename}\n")
  return None

if len(sys.argv) != 3:
  progname = sys.argv[0]
  sys.stderr.write(f"Usage: {progname} <zipfile> <destination_folder>\n")
  sys.exit(1)


# First, check whether the zip file contains a valid autorun file.
autorun = find_valid_autorun(sys.argv[1])

# Second, unzip the file properly.
# Use our super-duper ultra-fast zip file implementation!
with turbozipfile.ZipFile(sys.argv[1]) as z:
  z.extractall(sys.argv[2])

# Third, if we found a valid autorun in step 1, run it.
if autorun is None:
  sys.stderr.write(f"No valid autorun in file.")
  sys.exit(0)

python = sys.executable
if not python:
  if os.path.exists("/usr/bin/python3"):
    python = "/usr/bin/python3"
  elif os.path.exists("/usr/local/bin/python3"):
    python = "/usr/local/bin/python3"
  else:
    python = "python"

os.chdir(sys.argv[2])
p=os.path.join(".", autorun)
proc = subprocess.run([python, os.path.join(".", autorun)])
sys.exit(proc.returncode)
