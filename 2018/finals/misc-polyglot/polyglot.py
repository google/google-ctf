# Copyright 2018 Google LLC
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
import docker
import string
import shutil
import subprocess
import tempfile
import threading
import sys
import hashlib


def _rand_str():
  return "".join(random.choice(string.lowercase) for _ in range(10))


TIMEOUT = 20

FLAG = "CTF{sereno-tranquilo-mar-azul-de-abril}"


class Handler(object):

  def __enter__(self):
    self._files_to_clean = []
    return self

  def __exit__(self, type, value, traceback):
    if hasattr(self, "container"):
      self.container.kill()
    for file in self._files_to_clean:
      if os.path.isdir(file):
        shutil.rmtree(file)
      else:
        os.remove(file)

  # Unused additional filter.
  def binwalk_filter(self, file):
    errno, out_msg = self.container.exec_run("binwalk %s" % file)
    if errno != 0 or "pao_de_queijo" in out_msg:
      return "The Dark Lord caught your Pao de queijo"
    return ""

  def extract_general_files(self, client, zip_file, expected, first_general):
    """Take the zip_file and get a dict (file_name, sha256)"""
    self.container = client.containers.run(
        "general", "sleep 30", detach=True, remove=True)
    self.container.start()
    tmp_zip = os.path.join("/tmp/", _rand_str() + ".zip")
    base_res = _rand_str()
    res_dir = os.path.join("/tmp/", base_res)
    zip_tmpfile = tempfile.mktemp()
    self._files_to_clean.append(zip_tmpfile)
    with open(zip_tmpfile, "w") as f:
      f.write(base64.b64decode(zip_file))
    subprocess.call(
        "/usr/bin/docker cp %s %s:%s" % (zip_tmpfile, self.container.name,
                                         tmp_zip),
        shell=True)
    self.container.exec_run("mkdir %s" % res_dir)
    # print ">> " + tmp_zip
    # print ">> " + str(self.container.exec_run("ls /tmp"))
    if first_general:
      cmd = "7z e -o%s %s" % (res_dir, tmp_zip)
    else:
      cmd = "unzip -d %s %s" % (res_dir, tmp_zip)
    errno, out_msg = self.container.exec_run(cmd)
    # Manipulate output
    # tmp_tar_path = tempfile.mktemp()
    output_dir = tempfile.mkdtemp()
    self._files_to_clean.append(output_dir)
    subprocess.call(
        "docker cp %s:%s %s" % (self.container.name, res_dir, output_dir),
        shell=True)
    target_dir = os.path.join(output_dir, base_res)

    # Extract files from output
    def normalize(name, path):
      if name.startswith(path):
        return name[len(path):]
      return name

    file_names = set(
        f for f in os.listdir(target_dir)
        if os.path.isfile(os.path.join(target_dir, f)))
    extra = file_names - set(expected.keys())
    missing = set(expected.keys()) - file_names
    if extra or missing:
      return "\n".join([
          "Got files: %s" % file_names,
          "Extra files on the output: %s" % extra,
          "Missing files on the output: %s" % missing
      ])
    for fname in file_names:
      fpath = os.path.join(target_dir, fname)
      with open(fpath) as f:
        data = f.read()
        h = hashlib.sha256()
        h.update(data)
        if expected[fname] != h.hexdigest():
          return ("Contents for file %s don't match,"
                  " expected SHA256(%s) = %s" % (fname, fname, expected[fname]))
    if errno != 0 or "warning" in out_msg.lower() or "error" in out_msg.lower():
      return "There are warnings or errors, exit code: %d" % errno
    return ""

  def stage_zip(self):
    g1_expected = {
        "pao_de_queijo.txt":
            "6e6463d212a22ecdd1b539c1a3be62e8cea40f951521766db9e6b1f005a5c51d",
        "picanha.txt":
            "c72ad7261e8c32a5aee49af0721e94486a7bf04051a980cad790bb857c2aeb36",
        "header.txt":
            "c67d29fea817ed3ffba0ae99275a18d6cb058dbabfabcebcb1f4c904033ac536"
    }
    g2_expected = {
        "arepa.txt":
            "6dbb8dd2f8221cbaa9d023c893b7f1b6a603afc1d9cd740872bccaa7a6922f92",
        "cachapa.txt":
            "41860cc6ac5244df28842e834a8c9b55aba88534a5533284688b73404f747db7",
        "header.txt":
            "c67d29fea817ed3ffba0ae99275a18d6cb058dbabfabcebcb1f4c904033ac536",
    }
    print "Base64 zip file: "
    b64_msg = sys.stdin.readline().strip()
    print "Got it."
    client = docker.from_env()
    # General 1
    ret1 = self.extract_general_files(client, b64_msg, g1_expected, True)
    # general 2
    ret2 = self.extract_general_files(client, b64_msg, g2_expected, False)
    err = ""
    if ret1:
      err += "General 1 isn't happy: " + ret1 + "\n"
    if ret2:
      err += "General 2 isn't happy: " + ret2 + "\n"
    return err


def run_challenge(h):
  res = h.stage_zip()
  if res:
    print "Something went wrong:\n" + res
  else:
    print FLAG


def main():
  # If this is the first running this script, you need to load the general
  # image.
  # subprocess.call("/usr/bin/docker load -i general.image")
  with Handler() as h:
    challenge = threading.Thread(target=run_challenge, args=(h,))
    challenge.daemon = True
    challenge.start()
    challenge.join(TIMEOUT)
    if challenge.is_alive():
      print "Timeout! I'm done!"


if __name__ == "__main__":
  res = main()
