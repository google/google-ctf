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

from os import urandom
import signal


def _mul(x, y):
    if x == 0:
        x = 2**16
    if y == 0:
        y = 2**16
    z = x * y % (2**16 + 1)
    return z % 2**16


def _add(x, y):
    return (x + y) & 0xffff


class IDEA:
    def __init__(self, key: int, rounds=8):
        self.rounds = rounds
        sub_keys = []
        for i in range((rounds + 1) * 6):
            sub_keys.append((key >> (112 - 16 * (i % 8))) & 0xffff)
            if i % 8 == 7:
                key = ((key << 25) | (key >> 103)) % 2**128
        keys = []
        for i in range(rounds + 1):
            round_keys = sub_keys[6 * i: 6 * i + 6]
            keys.append(tuple(round_keys))
        self.keys = tuple(keys)

    def encrypt(self, plaintext: int):
        x1 = (plaintext >> 48) & 0xffff
        x2 = (plaintext >> 32) & 0xffff
        x3 = (plaintext >> 16) & 0xffff
        x4 = plaintext & 0xffff
        for i in range(self.rounds):
            k1, k2, k3, k4, k5, k6 = self.keys[i]
            x1, x2, x3, x4 = _mul(x1, k1), _add(x2, k2), _add(x3, k3), _mul(x4, k4)
            t0 = _mul(k5, x1 ^ x3)
            t1 = _mul(k6, _add(t0, x2 ^ x4))
            t2 = _add(t0, t1)
            x1, x2, x3, x4 = x1 ^ t1, x3 ^ t1, x2 ^ t2, x4 ^ t2

        k1, k2, k3, k4, k5, k6 = self.keys[self.rounds]
        y1, y2, y3, y4 = _mul(x1, k1), _add(x3, k2), _add(x2, k3), _mul(x4, k4)
        return (y1 << 48) | (y2 << 32) | (y3 << 16) | y4


class Challenge:
    def __init__(self):
        self.orig_key = int.from_bytes(urandom(16), 'big')
        self.key = self.orig_key
        self.cipher = IDEA(self.key, rounds=3)
        self.credits = 2024

    def flip_bits(self, mask):
        if self.credits > 0:
            self.credits -= 100 * mask.bit_count()
            self.key ^= mask
            self.cipher.__init__(self.key, rounds=3)

    def get_encryption(self, pt):
        if self.credits > 0:
            self.credits -= 1
            return self.cipher.encrypt(pt)
        return -1

    def get_flag(self, key_guess):
        if key_guess == self.orig_key:
            with open("flag.txt", "r") as f:
                FLAG = f.read()
            return FLAG
        raise Exception("you have no idea")


if __name__ == "__main__":
    chall = Challenge()
    PROMPT = ("Choose an API option\n"
              "1. Test Encryption\n"
              "2. Flip around some switches\n"
              "3. Get the flag\n"
              "4. Get balance\n")
    signal.alarm(512)
    while True:
        try:
            option=int(input(PROMPT))
            if option == 1:
                pt=int(input("(hex) text: "), 16)
                if not 0 <= pt < 2**64:
                    raise Exception("Inappropriate plain text")
                print(chall.get_encryption(pt))
            elif option == 2:
                mask=int(input("(hex) mask: "), 16)
                if not 0 <= mask < 2**128:
                    raise Exception("The switch you are trying to flip might be in another room")
                chall.flip_bits(mask)
            elif option == 3:
                key_guess=int(input("(hex) key_guess: "), 16)
                if not 0 <= key_guess < 2**128:
                    raise Exception("This key surely doesn't fit into my lock")
                print(chall.get_flag(key_guess))
                exit(0)
            elif option == 4:
                print("Credits Remaining:", chall.credits)
        except Exception as e:
            print(e)
            exit(1)
