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

use super::Direction;
use super::Enemy;
use super::Hitbox;
use super::Stats;
use super::Status;
use crate::enemy;
use crate::enemy::EnemyImpl;
use crate::res::enemies::EnemyType;
use crate::res::sprites::rabbit::Anim;

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
            x: 5,
            y: 0,
            w: 14,
            h: 32,
        },
    }
}

fn update_animation(enemy: &mut Enemy, walking: bool) {
    match enemy.status {
        Status::Dying { .. } => {
            enemy.sprite.maybe_set_animation(Anim::Die as usize);
        }
        Status::Idle => {
            let mut anim = Anim::Walk;
            if !walking {
                // Use the idle animation since we're not walking.
                anim = Anim::Idle;
            }
            enemy.sprite.maybe_set_animation(anim as usize);
            enemy.sprite.flip_h = match enemy.facing {
                Direction::Left => true,
                _ => false,
            };
        }
        Status::Damaged { cooldown } => {
            // Just started
            if cooldown == enemy::DAMAGE_COOLDOWN - 1 {
                enemy.sprite.set_animation(Anim::Damage as usize);
                enemy.sprite.flip_h = match enemy.facing {
                    Direction::Left => true,
                    _ => false,
                }
            }
        }
        _ => {}
    }
    enemy.sprite.update();
}
