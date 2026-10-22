// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an AS IS BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.



const PLAYER_SPRITE_WIDTH: i16 = 40;

/// "Random" offsets of the 2 explosion sprites that appear during the boss defeat sequence.
pub const EXPLOSION_OFFSETS: [[(i16, i16); 8]; 2] = [
    [
        (-47, -37),
        (33, 27),
        (54, -20),
        (35, -34),
        (47, -14),
        (32, 14),
        (-1, -6),
        (25, -25),
    ],
    [
        (-39, -13),
        (-38, -13),
        (-36, 22),
        (-19, -32),
        (4, 13),
        (-53, -38),
        (38, 9),
        (-53, 15),
    ],
];

/// Returns the offset of the player's projectile weapon
pub fn projectile_weapon_offset(flip_h: bool) -> (i16, i16) {
    const PROJECTILE_SIZE: i16 = 16;
    const PLAYER_HAND_X: i16 = 34;
    const PLAYER_HAND_Y: i16 = 22;

    let hand_x = if flip_h {
        PLAYER_SPRITE_WIDTH - PLAYER_HAND_X
    } else {
        PLAYER_HAND_X
    };
    (
        hand_x - PROJECTILE_SIZE / 2,
        PLAYER_HAND_Y - PROJECTILE_SIZE / 2,
    )
}


