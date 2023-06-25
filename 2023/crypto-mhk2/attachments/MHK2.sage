# Copyright 2023 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     https://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import secrets

random = secrets.SystemRandom()

MSG = "CTF{????}"


class PrivateKey:
    def __init__(self, length: int = 256, keytup: tuple = ()):
        if keytup:
            self.s1, self.s2, self.s, self.p1, self.p2, self.e1, self.e2 = keytup
        else:
            while True:
                self.s1 = self._gen_sequence(length)
                self.p1 = sum(self.s1) + 2
                self.e1 = self._gen_pos_ints(self.p1)
                if is_prime(self.p1): break

            while True:
                self.s2 = self._gen_sequence(length)
                self.p2 = sum(self.s2) + 2
                self.e2 = self._gen_pos_ints(self.p2)
                if is_prime(self.p2): break

            self.s = [self.s1[i] + self.s2[i] for i in range(length)]
            assert self.p1 != self.p2

    def _gen_sequence(self, length: int) -> list[int]:
        return [random.getrandbits(128) for _ in range(length)]

    def _gen_pos_ints(self, p) -> int:
        return random.randint((p-1)//2, p-1)

    def export_secret(self):
        return {"s1": self.s1, "s2": self.s2, "s": self.s,
                "p1": self.p1, "p2": self.p2, "e1": self.e1, "e2": self.e2}


class PublicKey:
    def __init__(self, private_key: PrivateKey):
        self.a1 = [(private_key.e1 * s) % private_key.p1 for s in private_key.s1]
        self.a2 = [(private_key.e2 * s) % private_key.p2 for s in private_key.s2]

        self.b1 = [i % 2 for i in private_key.s1]
        self.b2 = [i % 2 for i in private_key.s2]
        self.b = [i % 2 for i in private_key.s]

        self.t = random.randint(1, 2)
        self.c = self.b1 if self.t == 1 else self.b2

    def public_key_export(self):
        return {"a1": self.a1, "a2": self.a2, "b": self.b, "c": self.c}


class MHK2:
    def __init__(
        self,
        length: int,
        private_key: PrivateKey = PrivateKey,
        public_key: PublicKey = PublicKey,
    ):
        self.private_key = private_key(length)
        self.public_key = public_key(self.private_key)

    def _random_bin_sequence(self, n):
        return [random.randint(0, 1) for _ in range(n)]

    def encrypt(self, msg: str):
        ciphertext = []
        msg_int = f'{(int.from_bytes(str.encode(msg), "big")):b}'
        for i in msg_int:
            ciphertext.append(self.encrypt_bit(int(i)))
        return ciphertext

    def decrypt(self, ciphertext):
        plaintext_bin = ""
        for i in ciphertext:
            plaintext_bin += str(self.decrypt_bit(i))

        split_bin = [plaintext_bin[i : i + 7] for i in range(0, len(plaintext_bin), 8)]

        plaintext = ""
        for seq in split_bin:
            plaintext += chr(int(seq, 2))
        return plaintext

    # single bit {0,1}
    def encrypt_bit(self, bit):
        r1 = self._random_bin_sequence(len(self.public_key.b))
        r2 = self._random_bin_sequence(len(self.public_key.b))

        m1 = sum([(self.public_key.b[i] * r1[i]) for i in range(len(r1))]) % 2
        m2 = sum([(self.public_key.b[i] * r2[i]) for i in range(len(r2))]) % 2

        eq = sum([(self.public_key.c[i] * r1[i]) for i in range(len(r1))]) == sum(
            [(self.public_key.c[i] * r2[i]) for i in range(len(r2))]
        )

        while m1 != bit or m2 != bit or not eq or r1 == r2:
            r1 = self._random_bin_sequence(len(self.public_key.b))
            r2 = self._random_bin_sequence(len(self.public_key.b))

            m1 = (
                sum(
                    [
                        (self.public_key.b[i] * r1[i])
                        for i in range(len(self.public_key.b))
                    ]
                )
                % 2
            )
            m2 = (
                sum(
                    [
                        (self.public_key.b[i] * r2[i])
                        for i in range(len(self.public_key.b))
                    ]
                )
                % 2
            )

            eq = sum(
                [(self.public_key.c[i] * r1[i]) for i in range(len(self.public_key.b))]
            ) == sum(
                [(self.public_key.c[i] * r2[i]) for i in range(len(self.public_key.b))]
            )

        C1 = sum([(self.public_key.a1[i] * r1[i]) for i in range(len(r1))])
        C2 = sum([(self.public_key.a2[i] * r2[i]) for i in range(len(r2))])
        return C1, C2

    def decrypt_bit(self, ciphertext: tuple[int, int]) -> int:
        C1, C2 = ciphertext
        M1 = (
            pow(self.private_key.e1, -1, self.private_key.p1) * C1 % self.private_key.p1
        )
        M2 = (
            pow(self.private_key.e2, -1, self.private_key.p2) * C2 % self.private_key.p2
        )
        m = (M1 + M2) % 2
        return m


def main():
    crypto = MHK2(256)
    ciphertext = crypto.encrypt(MSG)
    plaintext = crypto.decrypt(ciphertext)

    print(crypto.public_key.public_key_export())
    print(ciphertext)

    assert plaintext == MSG


if __name__ == "__main__":
    main()
