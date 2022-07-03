#!/usr/bin/env python3

import numpy as np

def split(array, nrows, ncols):
    """Split a matrix into sub-matrices."""
    r, h = array.shape
    return array.reshape(h//nrows, nrows, -1, ncols).swapaxes(1, 2).reshape(-1, nrows, ncols)

# Generate column-major 4x4x(4x4) identity matrix
x = np.identity(16)
nonce = split(x, 4, 4)
for n in nonce:
    print(', '.join(f'{x:.1f}f' for x in n.flatten()) + ',')
