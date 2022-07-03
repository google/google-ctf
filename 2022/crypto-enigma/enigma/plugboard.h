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

struct Plugboard {
 public:
    std::array<int, 26> wiring;

  explicit Plugboard(const std::vector<std::string>& plugs) : wiring(make_wiring(plugs)) {}
  Plugboard(const Plugboard& other) = default;
  Plugboard& operator=(const Plugboard& other) {
    this->wiring = other.wiring;
    return *this;
  }

  int forward(int c) const {
        return wiring[c];
    }

 private:
  static std::array<int, 26> make_wiring(const std::vector<std::string>& plugs) {
    std::array<int, 26> ret;
    for (int i = 0; i < ret.size(); ++i) {
      ret[i] = i;
    }

    for (const std::string& s : plugs) {
      ret[s[0]-65] = s[1]-65;
      ret[s[1]-65] = s[0]-65;
    }

    return ret;
  }
};

// The identity plugboard.
const Plugboard& pN = *new Plugboard({});
