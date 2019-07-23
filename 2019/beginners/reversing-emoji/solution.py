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

def print_solution():
  # The prime palindromes for larger numbers can be calculated by
  # pre-computing only odd palindromes in the required ranges and
  # doing a O(sqrt(n)) prime number check on them. We could also
  # leverage the fact that there's no prime-palindrome with an even
  # number of digits other than 11. For e.g., to find out all 5 digit
  # prime palindromes, we find out all the palindromes between 100000
  # and 99999 either by simple iteration or recursive generation. We
  # then filter out all composite numbers with the help of a O(sqrt(n))
  # prime number check. We repeat this process for 3, 5, 7 and 9 digit
  # palindromes.


  # Batch 1 numbers
  encrypted_numbers_batch1 = [106, 119, 113, 119, 49, 74, 172, 242, 216, 208,
            339, 264, 344, 267, 743, 660, 893, 892, 1007, 975,
            10319, 10550, 10503, 11342, 11504, 12533, 12741,
            12833, 13437, 13926, 13893, 14450, 14832, 15417,
            15505, 16094, 16285, 16599, 16758, 17488
          ]

  # 1st to 40th Prime palindrome numbers
  prime_palins_batch1 = [2, 3, 5, 7, 11, 101, 131, 151, 181,
                        191,313, 353, 373, 383, 727, 757, 787,
                        797, 919, 929, 10301, 10501, 10601, 11311,
                        11411, 12421, 12721, 12821, 13331, 13831,
                        13931, 14341, 14741, 15451, 15551, 16061,
                        16361, 16561, 16661, 17471
                        ]

  # Batch 2 numbers
  encrypted_numbers_batch2 = [93766, 93969, 94440, 94669, 94952, 94865, 95934,
            96354, 96443, 96815, 97280, 97604, 97850, 98426
          ]

  # 99th to 112th Prime palindrome numbers
  prime_palins_batch2 = [93739, 94049, 94349, 94649, 94849,
                         94949, 95959, 96269, 96469, 96769,
                         97379, 97579, 97879, 98389
                         ]

  # Batch 3 numbers
  encrypted_numbers_batch3 = [9916239, 9918082, 9919154, 9921394, 9923213, 9926376,
            9927388, 9931494, 9932289, 9935427, 9938304, 9957564,
            9965794, 9978842, 9980815, 9981858, 9989997, 100030045,
            100049982, 100059926, 100111100, 100131019, 100160922,
            100404094, 100656111, 100707036, 100767085, 100887990,
            100998966, 101030055, 101060206, 101141058
          ]

  # 765th to 796th Prime palindrome numbers
  prime_palins_batch3 = [9916199, 9918199, 9919199, 9921299, 9923299, 9926299, 9927299,
     9931399, 9932399, 9935399, 9938399, 9957599, 9965699, 9978799,
     9980899, 9981899, 9989899, 100030001, 100050001, 100060001,
     100111001, 100131001, 100161001, 100404001, 100656001, 100707001,
     100767001, 100888001, 100999001, 101030101, 101060101, 101141101
     ]

  for enc, prime_palin in zip(encrypted_numbers_batch1, prime_palins_batch1):
    print(chr(enc ^ prime_palin), end='')

  for enc, prime_palin in zip(encrypted_numbers_batch2, prime_palins_batch2):
    print(chr(enc ^ prime_palin), end='')

  for enc, prime_palin in zip(encrypted_numbers_batch3, prime_palins_batch3):
    print(chr(enc ^ prime_palin), end='')

  print("\n")

if __name__ == "__main__":
  print_solution()
