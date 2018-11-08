// Copyright 2018 Google LLC
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
#ifdef TEST
#include <stdio.h>

int main(void) {
  //puts("Enter password:");
  char input[64] = {0};
  char output[256] = {0};
  scanf("%63[^\n]", input);
  checker(input, output);
  puts(output);
  return 0;
}
#endif
