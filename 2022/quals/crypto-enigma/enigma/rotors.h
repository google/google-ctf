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

#include <array>
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <cstring>

struct Rotor {
 public:
  const std::string name;

  const std::array<int, 26> forward_wiring;
  const std::array<int, 26> backward_wiring;
  const std::array<bool, 26> notch_positions;

  int ring_setting;
  int rotor_position;

  Rotor(const std::string& name, const std::string& encoding,
        std::vector<int> notch_positions, int ring_setting = 0,
        int rotor_position = 0)
      : name(name),
        forward_wiring(DecodeWiring(encoding)),
        backward_wiring(InverseWiring(forward_wiring)),
        notch_positions(NotchPositions(notch_positions)),
        ring_setting(ring_setting),
        rotor_position(rotor_position) {}

  Rotor(const Rotor& other) = default;
  Rotor& operator=(const Rotor& other) = default;

  Rotor Duplicate(int ring_setting = -1, int rotor_position = -1) const {
    Rotor ret = *this;
    if (ring_setting != -1) ret.ring_setting = ring_setting;
    if (rotor_position != -1) ret.rotor_position = rotor_position;
    return ret;
  }

  int forward(int c) const {
    int ret = encipher(c, rotor_position, ring_setting, forward_wiring);
    return ret;
  }

  int backward(int c) const {
    int ret = encipher(c, rotor_position, ring_setting, backward_wiring);
    return ret;
  }

  bool is_at_notch() const {
    return notch_positions[rotor_position];
  }

  void turnover() { rotor_position = (rotor_position + 1) % 26; }

 private:
  static std::array<int, 26> DecodeWiring(const std::string& encoding) {
    std::array<int, 26> wiring;
    for (int i = 0; i < encoding.size(); i++) {
      wiring[i] = encoding[i] - 65;
    }
    return wiring;
  }

  static std::array<int, 26> InverseWiring(const std::array<int, 26>& wiring) {
    std::array<int, 26> inverse;
    for (int i = 0; i < wiring.size(); i++) {
      int forward = wiring[i];
      inverse[forward] = i;
    }
    return inverse;
  }

  static std::array<bool, 26> NotchPositions(
      const std::vector<int>& positions) {
    std::array<bool, 26> ret;
    memset(ret.data(), 0, ret.size());
    for (int pos : positions) {
      ret[pos] = true;
    }
    return ret;
  }

  static int encipher(int k, int pos, int ring, std::array<int, 26> mapping) {
    int shift = pos - ring;
    return (mapping[(k + shift + 26) % 26] - shift + 26) % 26;
  }
};

std::ostream& operator<<(std::ostream& os, const Rotor& rs) {
  os << rs.name << "[" << rs.rotor_position << "/" << rs.ring_setting << "]";
  return os;
}

// clang-format off
const Rotor& I    = *new Rotor("I",    "EKMFLGDQVZNTOWYHXUSPAIBRCJ", {16});
const Rotor& II   = *new Rotor("II",   "AJDKSIRUXBLHWTMCQGZNPYFVOE", {4});
const Rotor& III  = *new Rotor("III",  "BDFHJLCPRTXVZNYEIWGAKMUSQO", {21});
const Rotor& IV   = *new Rotor("IV",   "ESOVPZJAYQUIRHXLNFTGKDCMWB", {9});
const Rotor& V    = *new Rotor("V",    "VZBRGITYUPSDNHLXAWMJQOFECK", {25});
const Rotor& VI   = *new Rotor("VI",   "JPGVOUMFYQBENHZRDKASXLICTW", {12, 25});
const Rotor& VII  = *new Rotor("VII",  "NZJHGRCXMYSWBOUFAIVLPEKQDT", {12, 25});
const Rotor& VIII = *new Rotor("VIII", "FKQHTLXOCBJSPDZRAMEWNIUYGV", {12, 25});

// Not a real rotor - not used for encoding the ciphertext.
const Rotor& N    = *new Rotor   ("N",    "ABCDEFGHIJKLMNOPQRSTUVWXYZ", {0});

const std::map<std::string, Rotor>& rotors = *new std::map<std::string, Rotor>({
  {I.name, I},
  {II.name, II},
  {III.name, III},
  {IV.name, IV},
  {V.name, V},
  {VI.name, VI},
  {VII.name, VII},
  {VIII.name, VIII},
  {N.name, N},
});
// clang-format on
