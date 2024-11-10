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

import logging
from interpreter.iicsa import *


class PunchCardReader:
    def __init__(self, raw):
        self.raw = raw
        self.program = ""
        self.punch_cards = []

    def validate(self):
        for r in self.raw:
            if r not in '01[, ]\n':
                logging.error(f"Invalid character: {r}")
                return False
        return True

    def parse(self):
        if not self.validate():
            return False
        try:
            logging.info(self.raw)
            self.punch_cards = eval(self.raw)
        except Exception as e:
            logging.error(f"Invalid format: {e}")
            return False
        return True

    def run(self):
        if not self.parse():
            return
        logging.info(f"Running program: {self.punch_cards}")
        res = []
        try:
            for p in self.punch_cards:
                chars = self.transpose(p)
                if len(chars) != 80:
                    raise Exception("invalid card")
                for c in chars[:-7]:
                    res.append(self.get_char(c))
        except Exception as e:
            logging.error(f"Failed to parse program: {e}")

        self.program = bytes(res).decode('cp1141')

    def get_char(self, column):
        if 11 > len(column) or len(column) > 13:
            raise Exception("learn how to code")
        return self.translate_column(column)

    def translate_column(self, column):
        punched = []
        for i in range(len(column)):
            if column[i] == 1:
                punched.append(i)
        print(punched)
        logging.info(punched)
        h = self.row_to_hex(punched)
        print(f"Got new char: {h}")

        return h

    @staticmethod
    def contains(set_a, set_b):
        for i in set_a:
            if i not in set_b:
                return False
        return True

    @staticmethod
    def reformat_indices(arr):
        res = []
        d = {
            0: 12,
            1: 11,
            2: 0,
            3: 1,
            4: 2,
            5: 3,
            6: 4,
            7: 5,
            8: 6,
            9: 7,
            10: 8,
            11: 9
        }
        for i in arr:
            res.append(d[i])
        return res

    def row_to_hex(self, punched):
        punched_clean = self.reformat_indices(punched)
        print(f"punched_clean: {punched_clean}")
        h = 0
        carry = 0
        if len(punched_clean) == 3:
            carry = 0x80
            punched_clean.remove(8)
            h = 8
        if self.contains([12], punched_clean):
            h += 0xC0 - carry
            punched_clean.remove(12)
        elif self.contains([11], punched_clean):
            h += 0xD0 - carry
            punched_clean.remove(11)
        elif self.contains([0], punched_clean):
            h += 0xE0 - carry
            punched_clean.remove(0)
        else:
            h += 0xF0 - carry

        for i in range(10):
            if self.contains([i], punched_clean):
                h += i
                punched_clean.remove(i)
                break

        if len(punched_clean) != 0:
            raise Exception(f"Invalid punch: {punched_clean}")

        return h

    @staticmethod
    def transpose(matrix):
        return [list(row) for row in zip(*matrix)]



