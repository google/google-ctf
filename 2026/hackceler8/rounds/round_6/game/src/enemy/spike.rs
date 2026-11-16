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

use super::Enemy;
use super::Hitbox;
use super::Stats;
use crate::enemy::EnemyImpl;
use crate::res::enemies::EnemyType;

pub(crate) fn new() -> EnemyImpl {
    EnemyImpl {
        stats,
        update_animation,
    }
}

fn stats(_: EnemyType) -> Stats {
    Stats {
        speed: 32,
        health: 2,
        strength: 0,
        melee: false,
        shoots: false,
        hitbox: Hitbox {
            x: 0,
            y: 0,
            w: 16,
            h: 16,
        },
    }
}

fn update_animation(enemy: &mut Enemy, _walking: bool) {
    enemy.sprite.update();
}
