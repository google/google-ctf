#!/usr/bin/python
# Copyright 2018 Google LLC
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

import hashlib

def check(s):
  def get():
    def get():
      def get():
        def get():
          def get():
            def get():
              def get():
                return ["5ef3f2aae145166cbc0b738afab2f8d90c299edee5eb4051107395e3ba637a86","3fdc49f4aefc086588cf75289178a44351a85033e6c7e9e4a3337e716f3f221f","5d5b77b0dd736777b522fc19572e5a71d4bb29cfdf78979efca3dca8361bda74","7eeecf1e3339198b2a08d7738ee59ded2449be5f34057383b0f830bd19fb7968","5093702094d4c2f8b72c3b32adfea3cc150e66fd1fced73f5b6a10b8910db337","ba2853f7fbe062df0e86cd12719e2af0eda18a4583f72604a318a99a970d3fc7","29a057c4102f371edce5b2baf29f330a645092b7918a91ba1e45baecf94cda13","7eeecf1e3339198b2a08d7738ee59ded2449be5f34057383b0f830bd19fb7968","a734ff7b5532da3189d49dcf395e85244f4aaf9052ad24ec14563301c030a095","8aba9e709af71b3d2d38b50e0debe42253e076f57adfa47a4a33092ff17eb27d","fc52dad433d9cf4ca2be74096d3c9ea3c5ac7e81edc2cb44d06aeef09b52b551","2e874850ba1dc08874ddde324ae2d0701497c26ff3a7ec425b9a1a139bf717e8","3a7b0788327b208bb25af82aa02d0106f74f21b3b9d28da591422f71b460569c","4e234ce843218d3c569a5a3d1565a578ec81573401093198d4cdb62e52f00f35","ba2853f7fbe062df0e86cd12719e2af0eda18a4583f72604a318a99a970d3fc7","fc52dad433d9cf4ca2be74096d3c9ea3c5ac7e81edc2cb44d06aeef09b52b551","68b85128461450d83b626fede97057d87ce1789d80ac8012521059567d2db799",]
              return get()
            return get()
          return get()
        return get()
      return get()
    return get()

  v = get()
  if len(v) != len(s):
    return False

  return all([
    hashlib.sha256("SUFFIX" + ch + "PREFIX").hexdigest() == tst
    for ch, tst in zip(s, v)
    ])

