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

def decrypt(encryption, privkey, r):
    C, S, Q = privkey
    k = S.dimensions()[0]
    F = S[0][0].parent()
    D = codes.decoders.GRSBerlekampWelchDecoder(C)
    res = []
    for enc in encryption:
        if r:
            Sm = D.decode_to_message((enc * Q)[:-r]).list()
        else:
            Sm = D.decode_to_message(enc * Q).list()
        Sm = vector(Sm + [F(0)] * (-len(Sm) % k))
        res += Sm * S
    return decode_message(res, F)


def test_params(p, n, k, r, message_len):
    pubkey, privkey = gen_pubkey(p, n, k, r)
    C, S, Q = privkey
    D = codes.decoders.GRSBerlekampWelchDecoder(C)
    message = os.urandom(message_len)
    ec = encrypt(message, pubkey)
    dc = decrypt(ec, privkey, r)
    assert dc == message, "decryption invalid"
    cryptanalyzed = break_wieschebrink(pubkey, ec, r)
    assert cryptanalyzed == message


if __name__ == "__main__":
    load("../challenge/chall.sage")
    load("../challenge/solve.sage")
    primes = (next_prime(2**i) for i in range(6, 10))
    for p in primes:
        for n in [randint(p // 4, 3 * p // 4) for _ in range(2)]:
            for k in [randint(n // 4, 3 * n // 4) for _ in range(2)]:
                for r in [randint(0, min(k, 3 * n // 4 - k))
                          for _ in range(4)]:  # fails if k+r is close to 4n/5
                    message_len = randint(10, 1000)
                    print(f"validating {p=} {n=} {k=} {r=} {message_len=}:")
                    test_params(p, n, k, r, message_len)
