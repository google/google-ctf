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

# Map the pell conic to GF(p)ˆ*. Note that this map is only applicable for D a square mod p.
# See also https://arxiv.org/abs/2203.05290, Section 3.2.
class CurveFieldMap:
  def __init__(self, C):
    self.C = C
    self.s = tonelli_shanks(C.D, C.p)
  def point_to_field(self, P):
    return (P.x - self.s*P.y) % self.C.p
  def field_to_point(self, u):
    p = self.C.p
    x = (1 + u**2) * pow(2*u, p - 2, p) % p
    y = (1 - u**2) * pow(2*self.s*u, p - 2, p) % p
    return self.C @ (x, y)

# Map points to GF(p)ˆ*. Note that 3 is a square mod p.
C = Curve(0x34096DC6CE88B7D7CB09DE1FEC1EDF9B448D4BE9E341A9F6DC696EF4E4E213B3,
          0x3,
          0x34096DC6CE88B7D7CB09DE1FEC1EDF9B448D4BE9E341A9F6DC696EF4E4E213B2)
G = C @ (0x2, 0x1)
P = C @ (0x2FE4D1B7BA0F64D6E5BD5E4E8D55E898FF13B76974646D97BFDCD9DC688C0E2F, 0x8C33E2FC2957EFF24DD1CD5382169C3BFAAC2E75A900D322A8C84D3C641A27E)
map = CurveFieldMap(C)
u = map.point_to_field(G)
v = map.point_to_field(P)
print("p", C.p)
print("subgroup order", (C.p - 1) // 2)
print(u, v)

# Cado-NFS outputs for logs wrt. "random" basis:
log_u = 7797185697465868868197802026550217130540658886988752360703529504066867930948
log_v = 8883185604700605024234436697645921191164872927743556176990899909133895490469
q = (C.p - 1) // 2
print("priv =", hex(log_v * pow(log_u, q - 2, q) % q))
