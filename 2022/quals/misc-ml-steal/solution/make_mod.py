# Copyright 2022 Google LLC
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

import numba
import time
import pickle
import logging
from numba.pycc import CC


cc = CC('exploit_mod')

import numpy as np

import math


@cc.export('sample', 'f4[:](i8[:], f4[::1])')
def sample(xx, Params):

    itos = np.array([10, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 61, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126])
    stoi = np.array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 0, 29, 0, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    ParamW = Params[:134*512*512].reshape((134,512,512))
    ParamB = Params[134*512*512:].reshape((134,512))

    xx = stoi[xx]

    block_size = 128
    if True:
        x_cond = xx[-block_size:]

        idx = np.ascontiguousarray(x_cond)
        x = ParamW[0].T[idx,:128] + ParamW[1].T[:len(idx), :128]

        K = 16
        for i in range(8):

            dim = 128
            weight = ParamB[2+i*K][:dim]
            bias = ParamB[2+i*K+1][:dim]
            y =  (x - (x).sum(1).reshape((x.shape[0],1))/x.shape[1])
            v = y - (y).sum(1).reshape((x.shape[0],1))/y.shape[1]
            v = (v**2).sum(1).reshape((x.shape[0],1)) / (v.shape[1]-1)
            y /= np.sqrt(v + 1e-5)
            y *= weight
            y += bias
            ln = y

            n_head = 8
            T, C = x.shape;

            def Linear(i, x, ParamW, ParamB, di, do):
                weight = ParamW[i][:di, :do]
                return x @ weight + ParamB[i+1][:do]

            k = Linear(6+i*K+0, ln, ParamW, ParamB, 128, 128).reshape((T, n_head, C // n_head)).transpose((1, 0, 2))
            q = Linear(6+i*K+2, ln, ParamW, ParamB, 128, 128).reshape((T, n_head, C // n_head)).transpose((1, 0, 2))
            v = Linear(6+i*K+4, ln, ParamW, ParamB, 128, 128).reshape((T, n_head, C // n_head)).transpose((1, 0, 2))

            def matmul(a, b):
                c = np.zeros((a.shape[0], a.shape[1], b.shape[2]), dtype=np.float32)
                for i in range(a.shape[0]):
                    c[i,:,:] = a[i] @ b[i]
                return c


            att = (matmul(q, k.transpose((0,2,1)))) / np.array(np.sqrt(k.shape[-1]),dtype=np.float32)

            mask = (1-np.tril(np.ones((1, T, T), dtype=np.float32))) * 100
            att -= mask

            ex = np.exp(att)
            att = ex / ex.sum(axis=2).reshape((ex.shape[0], ex.shape[1], 1))
            y = matmul(att, v)
            y = np.ascontiguousarray(y.transpose((1, 0, 2))).reshape((T, C))

            csa = Linear(6+i*K+6, y, ParamW, ParamB, 128, 128)

            x = x + csa

            dim = 128
            weight = ParamB[4+i*K][:dim]
            bias = ParamB[4+i*K+1][:dim]
            y =  (x - (x).sum(1).reshape((x.shape[0],1))/x.shape[1])
            v = y - (y).sum(1).reshape((x.shape[0],1))/y.shape[1]
            v = (v**2).sum(1).reshape((x.shape[0],1)) / (v.shape[1]-1)
            y /= np.sqrt(v + 1e-5)
            y *= weight
            y += bias
            ln = y

            di, do = 128, 512
            weight = ParamW[14+i*K][:di, :do]
            lin = ln @ weight + ParamB[15+i*K][:do]

            z = np.maximum(lin, 0)

            x = np.ascontiguousarray(x) + Linear(16+i*K, np.ascontiguousarray(z), ParamW, ParamB, 512, 128)


        dim = 128
        i = 18+7*K
        weight = ParamB[i][:dim]
        bias = ParamB[i+1][:dim]
        y =  (x - (x).sum(1).reshape((x.shape[0],1))/x.shape[1])
        v = y - (y).sum(1).reshape((x.shape[0],1))/y.shape[1]
        v = (v**2).sum(1).reshape((x.shape[0],1)) / (v.shape[1]-1)
        y /= np.sqrt(v + 1e-5)
        y *= weight
        y += bias
        x = y

        i = 20+7*K
        di, do = 128, 94
        weight = ParamW[i][:di, :do]
        logits = x @ weight + ParamB[i+1][:do]

        def softmax(x):
            ex = np.exp(x)
            return ex / ex.sum(axis=1).reshape((ex.shape[0], 1))

        probs = softmax(logits)
        probs = probs[-1, :]
        return probs

if __name__ == '__main__':
    cc.compile()
