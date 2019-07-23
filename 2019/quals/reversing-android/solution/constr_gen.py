# Copyright 2019 Google LLC
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#   https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Prints out the z3 code needed to calculate the summed key (with 16 elements).

# To get the real key (with 32 elements) from that, we'll need to brute-force
# all 2^16 pair possibilities and see which one produces the correct hash.

key = []
decisions = [False, False, False, False, True, False, False, True, False, True, True, True, True, False, False, False, True, True, False, False, True, False, True, False, False, False, True, True, True, False, False, False, True, False, False, False, False, True, True, True, True, True, False, True, False]
place = 0

def mergeSort(arr):
  global place
  if len(arr) <= 1:
    return arr
  res = [0]*len(arr)
  mid = len(arr)//2
  L = arr[:mid]
  R = arr[mid:]

  L = mergeSort(L)
  R = mergeSort(R)

  i = j = k = 0

  while i < len(L) and j < len(R):
    if decisions[place]:
      print("s.add(%s < %s)" % (L[i], R[j]))
      res[k] = L[i]
      i+=1
    else:
      print("s.add(%s >= %s)" % (L[i], R[j]))
      res[k] = R[j]
      j+=1
    k+=1
    place+=1

  while i < len(L):
    res[k] = L[i]
    i+=1
    k+=1

  while j < len(R):
    res[k] = R[j]
    j+=1
    k+=1

  # print(res)
  return res

print("from z3 import *");
print("s = Solver()");
print("");

for i in range(16):
  key.append('k%d' % i)
  print("k%d = Int('k%d')" % (i, i))
  print("s.add(k%d >= 0, k%d <= 15)" % (i, i))

print("")

mergeSort(key)

print("")
print("print(s.check())")
print("m = s.model()")

for i in range(16):
  print("print(m[k%d])" % i)
