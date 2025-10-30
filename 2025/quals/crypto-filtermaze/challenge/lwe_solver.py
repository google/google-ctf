# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import numpy as np
from sage.all import (
  ZZ,
  Matrix,
  Zmod,
  block_matrix,
  diagonal_matrix,
  identity_matrix,
  vector,
  zero_matrix,
)


def lwe_solver(n, m, q, A, b, err_mags):
  Zq = Zmod(q)
  Aq = Matrix(Zq, A)
  bq = vector(Zq, b)
  Mq = diagonal_matrix(Zq, err_mags)

  Al = (Aq.T / Mq).change_ring(ZZ)
  bl = (bq / Mq).change_ring(ZZ)

  I = identity_matrix
  O = zero_matrix
  L = block_matrix(
    [
      [bl.row(), I(1)],
      [Al, O(n, 1)],
      [q * I(m), O(m, 1)],
    ]
  )

  for row in L.LLL():
    if row[-1] in {-1, 1}:
      if row[-1] == -1:
        row = -row
      if (np.abs(row[:-1]) <= 1).all():
        print("e_pred:", row[:-1])
        e_pred = vector(Zq, row[:-1]) * Mq
        return Aq.solve_right(bq - e_pred)
