# Copyright 2023 Google LLC
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
import logging
import zlib
import js2py
import base64

# Format is always the same: offset, length, kwargs (as eval), and vars to put in
checks = [
    [0, 121, 's=passw', 'a'],
    [389, 129, "something='flag', n=a", 'a'],
    [518, 114, "s=passw, n=3", 'tmp'],
    [215, 104, "a=tmp[2], b=' p4'", 'b'],
    [919, 69, "a=a, b=b", 'a'],
    [111, 104, "a=int(tmp[0][0]), b=1", 'c'],
    [919, 69, "a=a, b=c", 'a'],
    [111, 104, "a=int(tmp[0][0]), b=1", 'c'],
    [919, 69, "a=a, b=c", 'a'],
    [111, 104, "a=int(ord(tmp[0][-1])), b=108", 'c'],
    [919, 69, "a=a, b=c", 'a'],
    [111, 104, "a=chr(int(tmp[1][0:2])), b='\\r'", 'c'],
    [919, 69, "a=a, b=c", 'a'],
    [215, 104, "a=tmp[1][-1], b='k'", 'c'],
    [919, 69, "a=a, b=c", 'a'],
    [632, 69, "c='w', s=tmp[3]", 'c'],
    [919, 69, "a=a, b=c", 'a'],
    [632, 69, "c=' ', s=tmp[0]", 'c'],
    [919, 69, "a=a, b=c", 'a'],
    [701, 140, "s=str(ord)[-4:-1]", 'tts'],
    [215, 104, "a=tmp[-1], b=tts", 'c'],
    [919, 69, "a=a, b=c", 'a'],
    [215, 104, "a=tmp[3][:2], b='ss'", 'c'],
    [919, 69, "a=a, b=c", 'a'],
]


class DynamoCheker:
    def __init__(self, raw):
        self.raw = bytes.fromhex(raw)
        self.fct = None
        self.tmp = None

    def parse_offset(self, offset, length):
        return zlib.decompress(self.raw[offset:length])

    def exec(self, offset, length, **kwargs):
        exec(base64.b64decode(zlib.decompress(self.raw[offset:offset + length])))
        return self.fct(**kwargs)

    def check2(self, passw):
        for i in checks:
            try:
                exec(f'{i[-1]} = self.exec(i[0], i[1], {i[2]})')
            except Exception as e:
                return False

        return eval('a')


def check_one(s):
    cool_string_thats_just_here_for_show = '789c73ce0dca89ca74ca8d340ecc4faecc3673ce744cf77476aa8c8a08324cce35494fccf3ad4cf6c82e8d8a88ca4872b32c4caeccc8f532aac8497176aaf2743148f7cc2ba94a0bf634f7f4f02d4d720f2b8d320ecaf7aaccf64e360a2b8eca3405999b1e100c36df1b0008be2550789c73ce0dca89ca74ca8d340ecc8f0c2e4f8fcccc3673ce744cf774762a008a6778bae75479ba7b42c520383937cc2025c2abd4d32da832253cd41b2ceee19593e211569994e9e41e195e511515585015155e91eb931b9595e2ec68e9e90ea41df36d016554263a789c73ce0dca89ca74ca8d340ecc8f0c2e4f8fcccc3673ce744cf774762a008a6778ba18587aba7b42c520383937cc2025c2abd4d32da832253cd41b2ceee19593e211569994e9e41e195e511515585015155e91eb931b9595e2ec083403483be6db02003e9225ba789c73ce0dca89ca74ca8d340ecc4faecc3673ce744cf77476aa8c8a08324cce35494f362c36f3cf34a888082ca88a0aafc8f5c98dca4a7176b4f47407d28ef9b600cb4615ee789c4dcddb0a83200000d05f8a42468f5318a96b544a17dfd2918ab746ebc1bf1fdbd37ee01c14062f2c0c4bd52755d66f310f699d40bc2378529e2846578d1be29fcd98a585bb8c7d92d6e98e177a8d6d568d3bc52c8cbcd52f954d2015342a3e3c9b404111b9fc9b1bc347cb979d644755391ec282efab3bf6fbe90752d33007789c73ce0dca89ca74ca8d340ecc4fae2c4f4fcacc3673ce744cf77476aa8c8a08324cce35490f37f64b4a0c2928f0742e4e4fca31488fcab5acf474cf4e4f0c37494fce752b8d320acdf77506ea750f2bf5f6f02df071762af50e33f04e360a2b8eca3405999d1e100cb6c31b009a822646789c8b720fcbf5748fca4a71cec8f27176aaf20ec9f7f674764cf7f4f0ca49f108ab4cca74caf274cf29f5f4f0f54e360a2b8eca34cd8d340e4c0f087602d1b600bdb41550789c2d8ed10e822018465f89e972eb1268d10fb6656e56dcd58f2352c4ad69e1d367d9c57777beb3c3fdb1d58ef94b5a048c4dc61db5c059031b62eb684639052b27dae59c76d71233e0f8962951c0674ee8111deb41b40388e2ff5d8691ae61b71fd057af9bd83e7479eff3d97b4a5aa38ab030be22e62c87995398544fed56df0e7b287f3dea0328d6343a789c73ce0dca89ca74ca8d340ecc4f360a2b8eca2c4f8f0cce3673ce744cf77476aa8a0aafc8f5c90bcaf0c9752b4f760f2b8d72cec8f00e2c8088e74665a5383b5a7aba0369c77c5b000c3c1ad6789c8b720fcbf5748fca4a71cec8f071f72cf04fcf4ff774764c4fce0d334889f02af574774d8f0c37cdf674f7f44e360a2b8eca34cd8d340e4c0f087602d1de00beda153e'

    d = DynamoCheker(cool_string_thats_just_here_for_show)
    return d.check2(s)
