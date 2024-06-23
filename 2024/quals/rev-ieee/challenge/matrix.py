# Copyright 2024 Google LLC
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
import numpy as np
import numpy.linalg

x1, x2, y1, y2 = 5, 4, 3, 2
a, b, c, d = 1, 1, -8, 1

bvec = np.array([a,b,c,d])
amat = np.array([
    [1, x1, y1, x1*y1],
    [1, x2, y1, x2*y1],
    [1, x1, y2, x1*y2],
    [1, x2, y2, x2*y2],
])

pqrs = numpy.linalg.solve(amat, bvec)
# z = p + qx + ry + sxy
print(pqrs)
