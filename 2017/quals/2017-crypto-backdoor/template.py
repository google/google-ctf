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

if __name__ == "__main__":

  from secret_data import aliceSecret, bobSecret, flag

  assert A == mul(aliceSecret, g, p)
  assert B == mul(bobSecret, g, p)

  aliceMS = mul(aliceSecret, B, p)
  bobMS = mul(bobSecret, A, p)
  assert aliceMS == bobMS
  masterSecret = aliceMS[0]*aliceMS[1]

  length = len(flag)
  encrypted_message = encrypt(I(flag), masterSecret)
  print "length = %d, encrypted_message = %d" % (length, encrypted_message)
