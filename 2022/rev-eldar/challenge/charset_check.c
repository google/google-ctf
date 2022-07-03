// Copyright 2022 Google LLC
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

#define u8 unsigned char

long int check(u8* serial) {
    int i = 0;
    int result = 0;
    for (; i < 28; i++)
        result |= serial[i] <= 32 || serial[i] >= 127;
    result |= serial[i];
    return result;
}

long int check_end(u8* key) {
    return 0;
}

void datadump(u8* buf, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", buf[i]);
        printf(i % 16 == 15 ? "\n" : " ");
    }
    if (len % 16 != 0)
        printf("\n");
}


int main() {
    datadump(check, check_end - check);
    FILE* f = fopen("charset_check.bin", "wb");
    fwrite(check, check_end - check, 1, f);
    fclose(f);
    return 0;
}
