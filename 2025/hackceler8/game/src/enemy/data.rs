// Copyright 2025 Google LLC
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

use super::Direction;
use crate::res::enemies::EnemyType;

/// Returns the offset of the crown sprite for a miniboss of the given type facing a given direction
pub fn crown_offset(enemy_type: EnemyType, facing: Direction) -> (i16, i16) {
    match enemy_type {
        EnemyType::Angel => match facing {
            Direction::Left => (-1, -25),
            _ => (1, -25),
        },
        EnemyType::Octopus => match facing {
            Direction::Left => (-1, -22),
            _ => (1, -22),
        },
        EnemyType::Goblin | EnemyType::Orc => match facing {
            Direction::Left | Direction::Up => (-1, -31),
            Direction::Right | Direction::Down => (1, -31),
        },
        EnemyType::Siren => match facing {
            Direction::Left | Direction::Up => (-2, -30),
            Direction::Right | Direction::Down => (2, -30),
        },
        EnemyType::Blob => (0, -23),
        EnemyType::Flameboi => (0, -18),
        EnemyType::Archer => match facing {
            Direction::Left => (3, -31),
            Direction::Right => (-3, -31),
            Direction::Up => (0, -32),
            Direction::Down => (0, -32),
        },
        _ => {
            panic!("Enemy can't be a miniboss")
        }
    }
}
