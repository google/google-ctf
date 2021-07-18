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

import subprocess
import random
import os
import pathlib
import shutil

# -DCTR=1 -DBADSTUFF_3=1 -DBADDATA_1=1 -DRAND_3=1 -DDEFENSE_5=1

num_builds = 18

badstuff_rand = random.Random(123)
baddata_rand = random.Random(252)
rand_rand = random.Random(323)
defense_rand = random.Random(234)
crypto_rand = random.Random(55)
opt_rand = random.Random(621)
target_rand = random.Random(751)
xorstr_rand = random.Random(8)
sbox_rand = random.Random(9)

def gen_baddata(rand):
  return f"-DBADDATA_{rand.randint(1, 3)}=1 "

def gen_badstuff(rand):
  badstuff = rand.choice([1, 2, 3])
  if badstuff == 1:
    badvalue = 1
  elif badstuff == 2:
    badvalue = rand.randint(0, 2)
  elif badstuff == 3:
    badvalue = rand.randint(1, 2)
  return f"-DBADSTUFF_{badstuff}={badvalue} "



def gen_rand(rand):
  return f"-DRAND_{rand.randint(1, 3)}={rand.randint(1, 94508123)} "

def gen_crypto(rand):
  choice = rand.choice(["CTR", "ECB", "CBC"])
  return f"-D{choice}=1 "

def gen_opt(rand):
  x = rand.choice(["-O0", "-O1", "-O2", "-O3", "-Ofast", "-Os"])
  return x

def gen_target(rand):
  #choices = []
  choices = ["polymorph", "polymorph_static", "polymorph_static_packed", "polymorph_dynamic_packed"]
  choices *= 3
  choices += ["polymorph_python", "polymorph_zsh"]
  choices += ["polymorph_static_python", "polymorph_static_zsh"]
  choices += ["polymorph_dynamic_packed_python", "polymorph_dynamic_packed_zsh"]
  return rand.choice(choices)

def gen_defense(rand):
  ret = ""
  while len(ret) == 0:
    if rand.randint(0, 4) == 0:
      ret += f"-DDEFENSE_1=1 "
    if rand.randint(0, 4) == 0:
      ret += f"-DDEFENSE_2=1 "
    if rand.randint(0, 4) == 0:
      ret += f"-DDEFENSE_3=1 "
    if rand.randint(0, 4) == 0:
      ret += f"-DDEFENSE_4=1 "
    if rand.randint(0, 4) == 0:
      ret += f"-DDEFENSE_5=1 "
  return ret

def gen_xorstr(rand):
  val = rand.randint(0, 2**32-1)
  return f"-DCOMPILER_SEED={val} "

def gen_sbox(rand):
  val = rand.randint(0, 2**64-1).to_bytes(8, "little")
  val0 = val[0]
  val1 = val[1]
  val2 = val[2]
  val3 = val[3]
  val4 = val[4]
  val5 = val[5]
  val6 = val[6]
  val7 = val[7]
  val = int.from_bytes(val, "little")
  return f"-DSBOX_XOR_FILTER={val}ULL -DSBOX_XOR_FILTER_0={val0} -DSBOX_XOR_FILTER_1={val1} -DSBOX_XOR_FILTER_2={val2} -DSBOX_XOR_FILTER_3={val3} -DSBOX_XOR_FILTER_4={val4} -DSBOX_XOR_FILTER_5={val5} -DSBOX_XOR_FILTER_6={val6} -DSBOX_XOR_FILTER_7={val7}"

def make(command, environ=os.environ):
  subprocess.run(
      ["make"] + command,
      env=environ, check=True)

def build():
  make(["clean"])

  badstuff = gen_badstuff(badstuff_rand)
  baddata = gen_baddata(baddata_rand)
  rand = gen_rand(rand_rand)
  defense = gen_defense(defense_rand)
  crypto = gen_crypto(crypto_rand)
  opt = gen_opt(opt_rand)
  target = gen_target(target_rand)
  xorstr = gen_xorstr(xorstr_rand)
  sbox = gen_sbox(sbox_rand)

  cxx = f"g++ {badstuff}{baddata}{rand}{defense}{crypto}{xorstr}{sbox}"
  print(cxx)

  environ = {**os.environ, "CXX": cxx, "POLYMORPH_OPT": opt}
  make([target], environ=environ)

  return target


def mv(fro, to):
  subprocess.run(
      ["mv", fro, to], check=True)


pathlib.Path("./build").mkdir(parents=True, exist_ok=True)
for i in range(num_builds):
  polymorph = build()
  mv(polymorph, f"build/polymorph{i}")


make(["clean"])
