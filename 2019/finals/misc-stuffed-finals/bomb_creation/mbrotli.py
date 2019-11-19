# Copyright 2019 Google LLC
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

# My brotli library.
# Contains constants useful for encoding and decoding.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import huffman

# All huffman code values in this file have the least significant bit first.

WBITS_code_pairs = [
    (10, '0100001'),
    (11, '0110001'),
    (12, '1000001'),
    (13, '1010001'),
    (14, '1100001'),
    (15, '1110001'),
    (16, '      0'),
    (17, '0000001'),
    (18, '   0011'),
    (19, '   0101'),
    (20, '   0111'),
    (21, '   1001'),
    (22, '   1011'),
    (23, '   1101'),
    (24, '   1111'),
]
WBITS_encoder = {v: code for v, code in WBITS_code_pairs}
WBITS_huffman = huffman.MakeTreeFromPairs(WBITS_code_pairs)

# While this is a huffman code, due to the fixed width it's simpler to just
# decode using a dict.
MNIBBLES_encoder = {
    0: '11',
    4: '00',
    5: '01',
    6: '10',
}
MNIBBLES_decoder = {code: v for v, code in MNIBBLES_encoder.iteritems()}

NBLTYPES_code_pairs = [
    ((1,   0), '   0'),
    ((2,   0), '0001'),
    ((3,   1), '0011'),
    ((5,   2), '0101'),
    ((9,   3), '0111'),
    ((17,  4), '1001'),
    ((33,  5), '1011'),
    ((65,  6), '1101'),
    ((129, 7), '1111'),
]
NBLTYPES_huffman = huffman.MakeTreeFromPairs(NBLTYPES_code_pairs)

context_mode_names = ['LSB6', 'MSB6', 'UTF8', 'Signed']

# (extra_bits, min_length)  # code
# max_length = min_length + 2**extra_bits - 1
insert_length_codes = [
    (0, 0),  # 0
    (0, 1),  # 1
    (0, 2),  # 2
    (0, 3),  # 3
    (0, 4),  # 4
    (0, 5),  # 5
    (1, 6),  # 6
    (1, 8),  # 7
    (2, 10),  # 8
    (2, 14),  # 9
    (3, 18),  # 10
    (3, 26),  # 11
    (4, 34),  # 12
    (4, 50),  # 13
    (5, 66),  # 14
    (5, 98),  # 15
    (6, 130),  # 16
    (7, 194),  # 17
    (8, 322),  # 18
    (9, 578),  # 19
    (10, 1090),  # 20
    (12, 2114),  # 21
    (14, 6210),  # 22
    (24, 22594),  # 23
]
copy_length_codes = [
    (0, 2),  # 0
    (0, 3),  # 1
    (0, 4),  # 2
    (0, 5),  # 3
    (0, 6),  # 4
    (0, 7),  # 5
    (0, 8),  # 6
    (0, 9),  # 7
    (1, 10),  # 8
    (1, 12),  # 9
    (2, 14),  # 10
    (2, 18),  # 11
    (3, 22),  # 12
    (3, 30),  # 13
    (4, 38),  # 14
    (4, 54),  # 15
    (5, 70),  # 16
    (5, 102),  # 17
    (6, 134),  # 18
    (7, 198),  # 19
    (8, 326),  # 20
    (9, 582),  # 21
    (10, 1094),  # 22
    (24, 2118),  # 23
]

max_meta_block_size = 16777216
