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

// Author: Ian Eldred Pudney

#include <iostream>
#include <string>
#include <set>
#include "enigma.h"

// This command line pales in comparison to Google's command lines.
const char* usage = " <left_rotor> <middle_rotor> <right_rotor> <left_ring_setting><middle_ring_setting><right_ring_setting> <plugboard_1_a><plugboard_1_b> <plugboard_2_a><plugboard_2_b> <plugboard_3_a><plugboard_3_b> <plugboard_4_a><plugboard_4_b> <plugboard_5_a><plugboard_5_b> <plugboard_6_a><plugboard_6_b> <plugboard_7_a><plugboard_7_b> <plugboard_8_a><plugboard_8_b> <plugboard_9_a><plugboard_9_b> <plugboard_10_a><plugboard_10_b> <left_rotor_pos><center_rotor_pos><right_rotor_pos>";

void bad_input(const char* progname, const char* sig="") {
  std::cerr << sig << " Usage: " << progname << usage << std::endl;
  exit(1);
}

template<typename Container>
void check_is_cap(const Container& buf) {
  for (char c : buf) {
    check_is_cap(c);
  }
}

template<>
void check_is_cap<char>(const char& c) {
  if (c >= 'A' && c <= 'Z') {
    return;
  }

  char b[2] = {c, '\0'};
  std::cerr << "Invalid configuration " << b << std::endl;
  exit(1);
}

int main(int argc, char** argv) {
  if (argc != 16) bad_input(argv[0]);

  std::string left_rotor_n = argv[1];
  std::string center_rotor_n = argv[2];
  std::string right_rotor_n = argv[3];

  if (left_rotor_n == center_rotor_n || center_rotor_n == right_rotor_n || left_rotor_n == right_rotor_n) {
    std::cerr << "A given rotor can only be used once." << std::endl;
    exit(1);
  }

  if (strlen(argv[4]) != 3) bad_input(argv[0]);
  check_is_cap(std::string(argv[4]));
  char left_ring_setting = argv[4][0];
  char center_ring_setting = argv[4][1];
  char right_ring_setting = argv[4][2];

  if (strlen(argv[5]) != 2) bad_input(argv[0]);
  if (strlen(argv[6]) != 2) bad_input(argv[0]);
  if (strlen(argv[7]) != 2) bad_input(argv[0]);
  if (strlen(argv[8]) != 2) bad_input(argv[0]);
  if (strlen(argv[9]) != 2) bad_input(argv[0]);
  if (strlen(argv[10]) != 2) bad_input(argv[0]);
  std::vector<std::string> plugboard_pairs = {argv[5], argv[6], argv[7], argv[8], argv[9], argv[10], argv[11], argv[12], argv[13], argv[14]};

  std::set<char> plugboard_chars;
  for (const std::string& p : plugboard_pairs) {
    plugboard_chars.insert(p[0]);
    plugboard_chars.insert(p[1]);
  }

  if (plugboard_chars.size() != 20) {
    std::cerr << "Duplicate plug provided - plug letters must be unique." << std::endl;
    exit(1);
  }

  check_is_cap(plugboard_chars);

  if (strlen(argv[15]) != 3) bad_input(argv[0]);
  check_is_cap(std::string(argv[15]));
  char left_rotor_pos = argv[15][0];
  char center_rotor_pos = argv[15][1];
  char right_rotor_pos = argv[15][2];

  if(!rotors.count(left_rotor_n) ||
     !rotors.count(center_rotor_n) ||
     !rotors.count(right_rotor_n)) {
    std::cerr << "Invalid rotor. Valid rotors are:\n";
    for (const auto& [k, _] : rotors) {
      std::cerr << "  " << k << "\n";
    }
    std::cerr << std::flush;
    exit(1);
  }

  Rotor left_rotor = rotors.at(left_rotor_n).Duplicate(left_ring_setting - 65, left_rotor_pos - 65);
  Rotor center_rotor = rotors.at(center_rotor_n).Duplicate(center_ring_setting - 65, center_rotor_pos - 65);
  Rotor right_rotor = rotors.at(right_rotor_n).Duplicate(right_ring_setting - 65, right_rotor_pos - 65);

  Plugboard plugboard(plugboard_pairs);

  Reflector reflector = B;

  Enigma enigma({left_rotor, center_rotor, right_rotor}, reflector, plugboard);

  while(!std::cin.eof()) {
    char c = std::cin.get();
    if (std::cin.eof()) break;
    if (c >= 'A' && c <= 'Z') {
      std::cout << enigma.encrypt(c) << std::flush;
    } else if (c == '\n' || c == ' ') {
      std::cout << c << std::flush;
    } else {
      std::cerr << "Unexpected character " << ((int)c) << " '" << c << "', can only encode capital letters." << std::endl;
      exit(-1);
    }
  }

  return 0;
}
