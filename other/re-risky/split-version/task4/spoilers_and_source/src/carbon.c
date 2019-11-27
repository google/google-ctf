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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

void banner(void) {
  puts("");
  puts("   \x1b[48;5;255;38;5;238m   _____           _                  \x1b[m");
  puts("  \x1b[48;5;254;38;5;237m   / ____|         | |                  \x1b[m");
  puts(" \x1b[48;5;253;38;5;236m   | |     __ _ _ __| |__   ___  _ __     \x1b[m");
  puts(" \x1b[48;5;252;38;5;235m   | |    / _` | '__| '_ \\ / _ \\| '_ \\    \x1b[m");
  puts(" \x1b[48;5;250;38;5;234m   | |___| (_| | |  | |_) | (_) | | | |   \x1b[m");
  puts("  \x1b[48;5;249;38;5;233m   \\_____\\__,_|_|  |_.__/ \\___/|_| |_|  \x1b[m");
  puts("   \x1b[48;5;248;38;5;232m   Winja CTF                    2018  \x1b[m");
  puts("");
}

bool check_4f0075(uint8_t ch) { return (ch ^ 0x63) == 0x05; }
bool check_d52e97(uint8_t ch) { return (ch ^ 0xa7) == 0xcb; }
bool check_3804b4(uint8_t ch) { return (ch ^ 0x06) == 0x67; }
bool check_898a37(uint8_t ch) { return (ch ^ 0x0b) == 0x6c; }
bool check_97e840(uint8_t ch) { return (ch ^ 0x93) == 0xe8; }
bool check_96db84(uint8_t ch) { return (ch ^ 0x5f) == 0x0f; }
bool check_61ffc3(uint8_t ch) { return (ch ^ 0xdd) == 0xaf; }
bool check_e47b15(uint8_t ch) { return (ch ^ 0xe2) == 0x87; }
bool check_497bba(uint8_t ch) { return (ch ^ 0x1b) == 0x6f; }
bool check_54f018(uint8_t ch) { return (ch ^ 0x99) == 0xed; }
bool check_6e41ad(uint8_t ch) { return (ch ^ 0xf7) == 0x8e; }
bool check_8651f5(uint8_t ch) { return (ch ^ 0xc1) == 0x93; }
bool check_98fcb8(uint8_t ch) { return (ch ^ 0xde) == 0xb7; }
bool check_8e9b08(uint8_t ch) { return (ch ^ 0x69) == 0x1a; }
bool check_6cd271(uint8_t ch) { return (ch ^ 0xaa) == 0xc1; }
bool check_ce64fe(uint8_t ch) { return (ch ^ 0x60) == 0x16; }
bool check_d2006b(uint8_t ch) { return (ch ^ 0x74) == 0x37; }
bool check_79cf3e(uint8_t ch) { return (ch ^ 0x6a) == 0x02; }
bool check_94d525(uint8_t ch) { return (ch ^ 0xa2) == 0xc3; }
bool check_3a857f(uint8_t ch) { return (ch ^ 0xb9) == 0xd5; }
bool check_471151(uint8_t ch) { return (ch ^ 0x2b) == 0x47; }
bool check_f0d55b(uint8_t ch) { return (ch ^ 0x13) == 0x76; }
bool check_3f6ea6(uint8_t ch) { return (ch ^ 0xac) == 0xc2; }
bool check_266f5e(uint8_t ch) { return (ch ^ 0xc4) == 0xa3; }
bool check_e084db(uint8_t ch) { return (ch ^ 0x72) == 0x17; }
bool check_a7d350(uint8_t ch) { return (ch ^ 0xa2) == 0xdf; }
bool check_7c1141(uint8_t ch) { return (ch ^ 0x2e) == 0x2e; }


int main(int argc, char **argv) {
  banner();

  if (argc != 2) {
    puts("usage: ./carbon <flag>");
    return 1;
  }

  char *flag = argv[1];

  if (check_4f0075(flag[0]))
  if (check_d52e97(flag[1]))
  if (check_3804b4(flag[2]))
  if (check_898a37(flag[3]))
  if (check_97e840(flag[4]))
  if (check_96db84(flag[5]))
  if (check_61ffc3(flag[6]))
  if (check_e47b15(flag[7]))
  if (check_497bba(flag[8]))
  if (check_54f018(flag[9]))
  if (check_6e41ad(flag[10]))
  if (check_8651f5(flag[11]))
  if (check_98fcb8(flag[12]))
  if (check_8e9b08(flag[13]))
  if (check_6cd271(flag[14]))
  if (check_ce64fe(flag[15]))
  if (check_d2006b(flag[16]))
  if (check_79cf3e(flag[17]))
  if (check_94d525(flag[18]))
  if (check_3a857f(flag[19]))
  if (check_471151(flag[20]))
  if (check_f0d55b(flag[21]))
  if (check_3f6ea6(flag[22]))
  if (check_266f5e(flag[23]))
  if (check_e084db(flag[24]))
  if (check_a7d350(flag[25]))
  if (check_7c1141(flag[26]))
    { puts("Well done!"); return 0; }
  return 1;

  return 0;
}
