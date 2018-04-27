// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.



_testcases = {
  '': [
    [[/*STDIN*/], /*EXPECTED_OUTPUT*/1]
  ],
  'hello_world': [
    [['hello, world', 1], '>hello, world!'],
    [['', 0], '>!'],
    [['', 3], '>!!!!!!'],
  ],
  'pow': [
    [[2, 2], 4],
    [[3, 2], 9],
    [[3, 3], 27],
    [[100, 2], 10000],
  ],
  'fibonacci': [
    [[1], 1],
    [[2], 1],
    [[3], 2],
    [[5], 5],
  ],
  'primes': [
    [[1], 2],
    [[2], 3],
    [[3], 5],
    [[5], 11],
    [[45], 197],
  ],
  'flag': flag.value.split('').map(function(EXPECTED_OUTPUT) {
    return [[/*STDIN*/], EXPECTED_OUTPUT];
  }),
};
