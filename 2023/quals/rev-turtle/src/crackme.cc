// g++ crackme.cc -o crackme && ./crackme
// g++ crackme.cc -o crackme && objdump -M intel -d crackme > crackme.disas

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
int cmpPos = 0;
#define M (sizeof(sortArr))
#define N (M+5)
char flag[N];
char sflag[M];

void genSortedFlag() {
  char* pflag = &(flag[4]);
  for (unsigned i = 0; i < M; ++i) { sflag[sortArr[i]] = pflag[i]; }
}

void binsearch(char c, const char* str, unsigned char n) {
  // char s[n+1];
  // s[n] = 0;
  // memcpy(s, str, n);
  // cout << c << " " << n << " " << s << endl;

  if (cmpPos == sizeof(cmpArr)) exit(0);

  if (n == 0) {
    // cout << "4" << " " << (int)cmpArr[cmpPos] << endl;
    if (cmpArr[cmpPos++] != 4) exit(0);
    return;
  }

  unsigned char m = (n-1)/2;
  // cout << c << " " <<  str[m] << endl;
  if (c < str[m]) {
    // cout<< "1" << " " << (int)cmpArr[cmpPos] << endl;
    if (cmpArr[cmpPos++] != 1) exit(0);
    binsearch(c, str, m);
  } else if (c > str[m]) {
    // cout << "2" << " " << (int)cmpArr[cmpPos] << endl;
    if (cmpArr[cmpPos++] != 2) exit(0);
    binsearch(c, &str[m+1], n-m-1);
  } else {
    // cout << "3" << " " << (int)cmpArr[cmpPos] << endl;
    if (cmpArr[cmpPos++] != 3) exit(0);
  }
}

void crackme() {
  if (flag[0] != 'C' || flag[1] != 'T' || flag[2] != 'F' || flag[3] != '{' || flag[N-1] != '}') {
    exit(0);
  }
  unsigned char found['z'-'+'+1];
  for (int i = 0; i < ('z'-'+'+1); ++i) {
    found[i] = 0;
  }
  for (int i = 4; i < M-1; ++i) {
    if (flag[i] < '+' || flag[i] > 'z') exit(0);
    if (found[flag[i]-'+'] == 255) {
      exit(0);
    }
    found[flag[i]-'+'] = 255;
  }

  genSortedFlag();
  // for (int i = 4; i < N-1; ++i) cout << flag[i];
  // cout << endl;
  // for (int i = 0; i < M; ++i) cout << sflag[i];
  // cout << endl;
  // cout << sizeof(cmpArr) << endl;
  cmpPos = 0;
  for (char c = '+'; c <= 'z'; ++c) {
    // cout << c << endl;
    binsearch(c, sflag, M);
  }
  exit(1);
}

int main(int argc, char **argv) {
  // cout << N << endl;
  // cout << M << endl;
  // cout << sizeof(cmpArr) << endl;
  memcpy(&flag, string("CTF{iT5_E-tUr+1es/AlL.7h3;waY:d0Wn}").c_str(), N);
  crackme();
  return 0;

  // for (int i = 4; i < N-1; ++i) {
  //   for (int cc = 0; cc < 256; ++cc) {
  //     memcpy(&flag, string("CTF{iT5_E-tUr+1es/AlL.7h3;waY:d0Wn}").c_str(), N);
  //     if (flag[i] == (char)cc) continue;
  //     char tmp = flag[i];
  //     flag[i] = (char)cc;
  //     for (int j = 4; j < N-1; ++j) {
  //       if (i == j) continue;
  //       if (flag[j] == (char)cc) {
  //         flag[j] = tmp;
  //         break;
  //       }
  //     }
  //     // cout << flag << endl;
  //     if (crackme()) {
  //       cout << "False positive flag: " << flag << endl;
  //     }
  //   }
  //   break;
  // }
  // return 0;
}
