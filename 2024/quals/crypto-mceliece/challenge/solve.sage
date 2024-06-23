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

from tqdm import tqdm


def square_dimension(G):
    k, n = G.dimensions()
    sp_mat = []
    for i in range(k):
        for j in range(i, k):
            sp_mat.append([a * b for a, b in zip(G[i], G[j])])
    return matrix(sp_mat).rank()


def decode_message(message, F):
    p = F.cardinality()
    res_int = 0
    message = message[:-int(message[-1])]
    for i in message[::-1]:
        res_int *= p
        res_int += int(i)
    res_int = int(res_int)
    return res_int.to_bytes((res_int.bit_length() + 7) // 8, 'big')


def sidelnikov_shestakov_alpha(G, ct):
    k, n = G.dimensions()
    F = G[0, 0].parent()
    M = G.echelon_form()
    for c in tqdm(F):
        if c == 0:
            continue
        alpha = [0] * n
        alpha[1] = 1
        bad_ratio = False
        for i in range(k, n):
            b = M[0][i] / M[1][i]
            if b == c:
                bad_ratio = True
                break
            alpha[i] = c / (c - b)
        if bad_ratio:
            continue

        for i in range(2, k):
            p, q = k, k + 1
            while True:
                bp = M[0][p] / M[i][p]
                bq = M[0][q] / M[i][q]
                A = bp / bq * (alpha[p] - alpha[0]) / (alpha[q] - alpha[0])
                if A == 1:
                    p += 1
                    q += 1
                    if q == n:
                        break
                    continue
                alpha[i] = (A * alpha[q] - alpha[p]) / (A - 1)
                break
        if len(set(alpha)) == n:
            C = codes.GeneralizedReedSolomonCode(alpha, k)
            D = codes.decoders.GRSBerlekampWelchDecoder(C)
            try:
                D.decode_to_code(ct)
                return D
            except Exception as e:
                continue


def break_wieschebrink(pubkey, ct, r):
    k, n = pubkey.dimensions()
    n -= r
    F = pubkey[0][0].parent()
    a = max(2 * k + r - n, 0)  # 0 when k < (n-r)/2
    random_cols = set()
    seen_pos = set()
    while len(random_cols) != r:
        shorten_pos = sample(list(set(range(n + r)) - seen_pos), a)
        seen_pos.update(shorten_pos)
        remaining = [i for i in range(n + r) if i not in shorten_pos]
        shortened_code = codes.LinearCode(pubkey).shortened(shorten_pos)
        G_shortened = shortened_code.generator_matrix()
        a1 = 2 * k - 1 + r - a - square_dimension(G_shortened)
        a0 = a - a1
        for i, v in tqdm(enumerate(remaining), total=int(n + r - a)):
            G_shortened_punctured = G_shortened.delete_columns([i])
            sq_dim = square_dimension(G_shortened_punctured)
            if sq_dim == 2 * (k - a1) + r - a0 - 2:
                random_cols.add(v)
        print("found {} out of {} random positions".format(len(random_cols), r))
    G_punctured = pubkey.delete_columns(random_cols)
    ct_punctured = [vector([ct_j[i] for i in range(
        n + r) if i not in random_cols]) for ct_j in ct]
    D_recover = sidelnikov_shestakov_alpha(G_punctured, ct_punctured[0])
    encoded_m = []
    for ct_j in ct_punctured:
        encoded_m += list(G_punctured.solve_left(D_recover.decode_to_code(ct_j)))
    F = pubkey[0][0].parent()
    return decode_message(encoded_m, F)


if __name__ == "__main__" and "__file__" in globals():
    pubkey = load("pubkey.sobj")
    flag_enc = list(load("flag_enc.sobj"))
    p, n, k, r = load("params.sobj")
    print(break_wieschebrink(pubkey, flag_enc, r))
