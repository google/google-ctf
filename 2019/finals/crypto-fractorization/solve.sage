# Copyright 2019 Google LLC
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

e = 65537
c = 0x59081114d5e0fe44922894787879caf778568dde06174a9ab498c9071176f52c9891e987adfac71e53b57e805e244f2667b8d7c098aabc045a9f4618f49300a70022b8642571ffb9948accd96a4943b950e0cd4f47246440b748dfd1ba67e9e966d40096d1a2a0ddcb8e31daf98a9865d2df78a8f72dedd6c656f38c92c6e90e995946126198a9d628758c0408b038954ba7f3dc33803305bcb8adbb67a3f50f4b0e5a49fce30853ee1971c556929e7327cee2476fe7737279871a03a7cd023bb3e8a056217bbbdd53480be56ee76c8a2128cf8f9aec36e9aec3631414031c90e1c7d90a7a7865d02138496382305ae1a92db9e249c8c130cb180a331359a261667ee5a1ef6a0908498b9fcff01c39ac9d99546dab9f17d35ec566d6b69c5d910509a4bf33922728890c4991a1804c4a49a7a874209671e570f368c5738081c4e31d0e76d970552d475332f97ff0c1115f5d7ca7b7a14994661aeb2bcf050240a424125a018d03cb0a5c6bde25b7c0a53912441834ff4579505c85750ef3ff00219084037902c8824065349762e09f3cf2fef589b74b315e9c77713a25890811ab3fa384858ff9e46b7d6dbcaf177fc5d701be0749c4c2e1c409b439830bc34c3d3284f27952b17c930cc9ef6cb6c9aace9a1f5024a21f46387f16470935d0bcc285aa8da3f38ffedef7e5c1f4ccf3968c0485437dcf5d5386afcd0f270e24c9 

n = 0xd3eaed980ca42c7957cd728b453e1e4dd81da1e6d3a124f10eb70d6fe8a070a6c5759463a960dce2e73c2f5f7405b5ffe0a25a0847afde6cb4dff6cc7c4b29f7bff5b3c5a4f160ce79b102f1b587775ca745e7ba9e427401b718b9d1be99f145d9c01b37fc24587aaab6edeea037249fc3c4c782bf19d7c71a5b250687dc18977a5e9a3321756ddc42eae8f7170e827c47848e24fadb8986c9ea1e6573e10088ce020b3d16c342a79fe069b940cf08d3beeaaf7ea51496b4f4de1100d16f7830a0d8789170bc477912c19337def818a68c363eccd09c882d781aeb0963cd8aae15280ba2dbe1af33b20b9112fb566ddb81fc292edbfbba0b9639f712e2a008ab9481b402581f269d5a78e8ea97d7bdf8ad276ace25a2995d85f2d32abdcf7a02bd03ac49c4fcef0b6ea6cc88103d975410cd8b6cd84e53f0fc42410520132598dc06efe2d231aaa8a1ae9b082dbf67dc43f58214cd17a04ea247f7e67d507b0472aa90840c87eb3731ca0aa26c98efe2323a991cd1b518211111f2f9ef885c4828fce7ad80a882bb9db95e20135528260f9466b3726a4f9c43e31349897085531fd8a6eb48dc02ce6c3e68ae18c88af8e4bce4c3c8ec7e6789d1fbd13b368bc5ca042b8b1ffa1b747d1a4e8415110e037f3acaeff0a9d04fc3558e51156a410316a58f31913f5d1a4009922556e488671f6ccc6fb05d2bdaeb6147fcac2d227f

pattern_size = 256
prime_size = 2048
x = 2**pattern_size
d0 = 2**pattern_size - 1
w = 2**prime_size
u, v = divmod(n, w)
M = matrix([[x, 0, u * d0 % w],
            [0, x, v * d0 % w],
            [0, 0,         w]])

for vec in M.LLL():
  bx, ax = vec[0], -vec[1]
  p = gcd(ax * w + bx, n)
  if 1 < p < n:
    q = n // p
    break

phi = (p-1)*(q-1)
d = inverse_mod(e, phi)
print(Integer(pow(c, d, n)).hex().decode('hex'))


