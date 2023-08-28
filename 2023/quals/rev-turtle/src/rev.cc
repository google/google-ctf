// g++ rev.cc -o rev && ./rev

// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <vector>
#include <algorithm>
using namespace std;

const char sortArr[] = {23,14,7,18,12,1,28,15,26,0,5,21,27,3,11,24,13,2,8,22,6,10,29,19,17,9,20,4,16,25};
const char cmpArr[] = {1,1,1,3,1,1,1,2,1,4,1,1,1,2,3,1,1,3,1,1,2,1,3,1,1,2,3,1,1,2,2,3,1,1,2,2,2,4,1,3,1,2,1,1,1,4,1,2,1,1,3,1,2,1,1,2,4,1,2,1,3,1,2,1,2,1,4,1,2,1,2,1,4,1,2,1,2,3,1,2,3,1,2,2,1,1,4,1,2,2,1,1,4,1,2,2,1,1,4,1,2,2,1,1,4,1,2,2,1,1,4,1,2,2,1,3,1,2,2,1,2,4,1,2,2,1,2,4,1,2,2,1,2,4,1,2,2,3,1,2,2,2,1,4,1,2,2,2,1,4,1,2,2,2,1,4,1,2,2,2,1,4,1,2,2,2,1,4,1,2,2,2,1,4,1,2,2,2,3,1,2,2,2,2,4,1,2,2,2,2,4,1,2,2,2,2,4,1,2,2,2,2,4,1,2,2,2,2,4,1,2,2,2,2,4,1,2,2,2,2,4,3,2,1,1,1,3,2,1,1,1,2,4,2,1,1,3,2,1,1,2,1,4,2,1,1,2,3,2,1,1,2,2,4,2,1,1,2,2,4,2,1,1,2,2,4,2,1,1,2,2,4,2,1,1,2,2,4,2,1,3,2,1,2,1,1,4,2,1,2,1,3,2,1,2,1,2,4,2,1,2,1,2,4,2,1,2,3,2,1,2,2,3,2,1,2,2,2,4,2,1,2,2,2,4,2,3,2,2,1,1,3,2,2,1,1,2,4,2,2,1,1,2,4,2,2,1,3,2,2,1,2,1,4,2,2,1,2,3,2,2,1,2,2,4,2,2,1,2,2,4,2,2,1,2,2,4,2,2,3,2,2,2,1,3,2,2,2,3,2,2,2,2,1,4,2,2,2,2,1,4,2,2,2,2,3,2,2,2,2,2,4,2,2,2,2,2,4,2,2,2,2,2,4};
#define M (sizeof(sortArr))
#define N (M+5)


int main(int argc, char **argv) {
  int cmpPos = 0;
  char sFlag[M+1];
  sFlag[M] = 0;
  for (char c = '+'; c <= 'z'; ++c) {
    int start = 0;
    int end = M-1;
    while (true) {
      cout << start << " " << end << endl;
      char cmp = cmpArr[cmpPos++];
      if (end < start) {
        if (cmp != 4) {
          cout << "char " << c << " should have reached 4 by now, is instead " << int(cmp) << " :|" << endl;
          return 1;
        }
        cout << c << " not in flag" << endl;
        break;
      }
      int mid = (start+end)/2;
      if (cmp == 1) {
        cout << 1 << endl;
        end = mid-1;
      } else if (cmp == 2) {
        cout << 2 << endl;
        start = mid+1;
      } else if (cmp == 3) {
        cout << 3 << endl;
        cout << "'" << c << "': pos " << mid << endl;
        sFlag[mid] = c;
        break;
      }
    }
  }
  cout << sFlag << endl;
  char flag[M+1];
  flag[M] = 0;
  for (unsigned i = 0; i < M; ++i) { flag[i] = sFlag[sortArr[i]]; }
  cout << "CTF{" << flag << "}" << endl;
  return 0;
}
