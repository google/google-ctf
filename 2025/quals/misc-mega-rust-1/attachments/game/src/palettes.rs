// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use megarust::*;

pub fn init(vdp: &mut impl Vdp) {
    // Sonk
    vdp.set_palette(
        Palette::A,
        &[
            4000, 548, 1339, 1379, 3493, 3214, 2776, 2526, 4095, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    // Wasp, spike, flag
    vdp.set_palette(
        Palette::B,
        &[
            0, 529, 802, 292, 1331, 2150, 2986, 943, 1759, 3821, 0, 1092, 1111, 882, 2457, 1002,
        ],
    );
    // Wasp iz dead :C
    vdp.set_palette(
        Palette::C,
        &[
            0, 4095, 4095, 4095, 4095, 4095, 4095, 4095, 4095, 4095, 4095, 4095, 4095, 4095, 4095,
            4095,
        ],
    );
    // Map
    vdp.set_palette(
        Palette::D,
        &[
            0, 0, 0, 5, 80, 2640, 1365, 90, 95, 160, 2730, 175, 4085, 250, 1535, 4095,
        ],
    );
}
