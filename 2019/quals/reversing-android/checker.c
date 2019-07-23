// Copyright 2019 Google LLC
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//   https://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// gcc -o checker checker.c; ./checker

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int decisions[] = {0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0,
                   0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0,
                   0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0};
int place = 0;
int correct = 0;

void MergeSort(char* arr, int len) {
  if (len <= 1) {
    return;
  }
  int len1 = len / 2;
  int len2 = len - len1;
  char* l = arr;
  char* r = arr + len1;

  MergeSort(arr, len1);
  if (!correct) {
    return;
  }
  MergeSort(r, len2);
  if (!correct) {
    return;
  }

  int i = 0, j = 0, k = 0;
  char temp[16];

  while (i < len1 && j < len2) {
    if (l[i] < r[j]) {
      if (decisions[place] != 1) {
        correct = 0;
        return;
      }
      ++place;

      temp[k] = l[i];
      ++i;
    } else if (l[i] > r[j]) {
      if (decisions[place] != 0) {
        correct = 0;
        return;
      }
      ++place;

      temp[k] = r[j];
      ++j;
    } else {
      correct = 0;
      return;
    }
    ++k;
  }
  while (i < len1) {
    temp[k] = l[i];
    ++i;
    ++k;
  }
  while (j < len2) {
    temp[k] = r[j];
    ++j;
    ++k;
  }
  memcpy(arr, temp, len);
}

int Checker(char* key) {
  char sum[16];
  for (int i = 0; i < 16; ++i) {
    sum[i] = key[2 * i] + key[2 * i + 1];
  }

  correct = 1;
  place = 0;
  MergeSort(sum, 16);
  return correct;
}

int main(int argc, char **argv) {
  // Sanity check 0: Returns true on correct key
  char correct_key[] = {9, 0, 0, 8, 0,  7, 2, 0, 0, 11, 0, 15, 13, 0, 10, 0,
                        6, 0, 0, 5, 14, 0, 0, 4, 0, 3,  0, 0,  12, 0, 1,  0};
  printf("Result for right key: %d\n", Checker(correct_key));

  // Sanity check 1: We shouldn't return true for a modified key
  printf("\nSanity check 1\n");
  for (int i = 0; i < 16; ++i) {
    for (int new_char = 1; new_char < 16; ++new_char) {
      // Replace the non-0 char
      int replace = 2 * i;
      if (correct_key[replace] == 0) {
        replace = 2 * i + 1;
      }
      printf("Replacing correct_key[%d] (%d) with %d\n", replace,
             correct_key[replace], new_char);

      // Insert new_char to key[replace]
      if (new_char == correct_key[replace]) {
        continue;
      }

      char bad_key[32];
      memcpy(bad_key, correct_key, 32);

      // Elements need to be unique, so replace the other new_char with current
      // key[replace]
      for (int j = 0; j < 32; ++j) {
        if (bad_key[j] == new_char) {
          bad_key[j] = bad_key[replace];
          break;
        }
      }

      bad_key[replace] = new_char;

      printf("Checking ");
      for (int j = 0; j < 32; ++j) {
        printf("%d ", bad_key[j]);
      }
      if (Checker(bad_key)) {
        puts(": Checker returns true :C");
        return 1;
      } else {
        puts(": Checker returns false");
      }
    }
  }

  // Sanity check 2: We should still return true if the sums stay the same
  printf("\nSanity check 2\n");
  for (int replace = 0; replace < 32; replace += 2) {
    char bad_key[32];
    memcpy(bad_key, correct_key, 32);
    for (int new_char = 0; new_char < 16; ++new_char) {
      if (new_char == correct_key[replace]) {
        continue;
      }
      int correct_sum = correct_key[replace] + correct_key[replace + 1];
      int other_char = correct_sum - new_char;
      if (other_char < 0 || other_char >= 16) {
        continue;
      }
      bad_key[replace] = new_char;
      bad_key[replace + 1] = other_char;
      printf("Checking ");
      for (int j = 0; j < 32; ++j) {
        printf("%d ", bad_key[j]);
      }
      if (!Checker(bad_key)) {
        puts(": Checker returns false :C");
        return 1;
      } else {
        puts(": Checker returns true");
      }
    }
  }
  return 0;
}
