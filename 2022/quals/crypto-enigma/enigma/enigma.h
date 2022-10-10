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

#include <string>

#include "rotors.h"
#include "reflector.h"
#include "plugboard.h"

struct Enigma {
 public:
    // 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25
    // A B C D E F G H I J K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z

    const Reflector reflector;
    const Plugboard plugboard;

    Rotor left_rotor;
    Rotor center_rotor;
    Rotor right_rotor;

    Enigma(const std::array<Rotor, 3>& rotors, Reflector reflector, Plugboard plugboard) : reflector(reflector), plugboard(plugboard), left_rotor(rotors[0]), center_rotor(rotors[1]), right_rotor(rotors[2]) {

    }

    int encrypt(int c) {
        rotate();

        // Plugboard in
        c = plugboard.forward(c);

        // Right to left
        c = right_rotor.forward(c);
        c = center_rotor.forward(c);
        c = left_rotor.forward(c);

        // Reflector
        c = reflector.forward(c);

        // Left to right
        c = left_rotor.backward(c);
        c = center_rotor.backward(c);
        c = right_rotor.backward(c);

        // Plugboard out
        c = plugboard.forward(c);

        return c;
    }

    char encrypt(char c) {
        return (char)(encrypt(c - 65) + 65);
    }

    std::string encrypt(const std::string& input) {
      std::string output = input;
        for (int i = 0; i < input.size(); i++) {
            output[i] = encrypt(input[i]);
        }
        return output;
    }

 private:
    void rotate() {
        // If center rotor notch - double-stepping
        if (center_rotor.is_at_notch()) {
            center_rotor.turnover();
            left_rotor.turnover();
        }
        // If left-rotor notch
        else if (right_rotor.is_at_notch()) {
            center_rotor.turnover();
        }

        // Increment right-most rotor
        right_rotor.turnover();
    }
};
