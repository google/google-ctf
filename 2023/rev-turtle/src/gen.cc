// g++ gen.cc -o gen && ./gen

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
#include <iostream>
#include <vector>
#include <algorithm>
using namespace std;

// CTF{iT5_E-tUr+1es/AlL.7h3;waY:d0Wn}
// CTF{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}
// CTF{0123456789abcdefghijklmnopqrst}
string flag = "iT5_E-tUr+1es/AlL.7h3;waY:d0Wn";

int binsearch(char c, const char* str, char n) {
  // cout << c << " " << str << endl;
  int l = 0;
  int r = n-1;
  while (l <= r) {
    int m = (l+r)/2;
    if (c < str[m]) {
      r = m-1;
      cout << "1,";
    } else if (c > str[m]) {
      l = m+1;
      cout << "2,";
    } else {
      cout << "3,";
      return m;
    }
  }
  cout << "4,";
  return -1;
}

int main(int argc, char **argv) {
  // Get sorted vector + index array to use for sorting
  vector<pair<char, int>> idx;
  for (int i = 0; i < flag.size(); ++i) {
    idx.push_back(make_pair(flag[i], i));
  }
  sort(idx.begin(), idx.end());
  vector<int> newLoc;
  for (const auto& i : idx) {
    newLoc.push_back(i.second);
  }
  vector<int> origLoc;
  for (const auto& i : newLoc) { origLoc.push_back(0); }
  for (int i = 0; i < newLoc.size(); ++i) { origLoc[newLoc[i]] = i; }

  cout << "{";
  for (const auto& i : origLoc) { cout << i << ","; }
  cout << "};" << endl;
  // for (const auto& f : flag) { cout << f << "  "; }
  // cout << endl;
  // for (const auto& i : idx) { cout << i.first << "  "; }
  // cout << endl;

  // Get the expected comparisons for the binary search
  sort(flag.begin(), flag.end());
  // cout << flag << endl;
  // for (const auto& f : flag) printf("%d ", f);
  // cout << endl;
  cout << "{";
  for (char c = '+'; c <= 'z'; ++c) {
    binsearch(c, flag.c_str(), flag.size());
  }
  cout << "};" << endl;

  return 0;
}
