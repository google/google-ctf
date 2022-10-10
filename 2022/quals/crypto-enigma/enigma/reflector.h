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
struct Reflector {
 public:
  const std::string name;
    const std::array<int, 26> forward_wiring;

  explicit Reflector(const std::string& name, const std::string& encoding) : name(name), forward_wiring(DecodeWiring(encoding)) {}

  int forward(int c) const {
      return forward_wiring[c];
  }
 private:
    static std::array<int, 26> DecodeWiring(const std::string& encoding) {
        std::array<int, 26> wiring;
        for (int i = 0; i < wiring.size(); i++) {
            wiring[i] = encoding[i] - 65;
        }
        return wiring;
    }

};



// The reflector in our Enigma.
const Reflector& B = *new Reflector("B", "YRUHQSLDPXNGOKMIEBFZCWVJAT");

// Another reflector, not used in our Enigma.
const Reflector& C = *new Reflector("C", "FVPJIAOYEDRZXWGCTKUQSBNMHL");

// The simple mirroring reflector, not a real reflector.
const Reflector& X = *new Reflector("X", "ZYXWVUTSRQPONMLKJIHGFEDCBA");
