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
use super::Enemy;
use super::Hitbox;
use super::Stats;
use super::Status;
use crate::enemy;
use crate::enemy::EnemyImpl;
use crate::res::enemies::EnemyType;
use crate::res::sprites::orc::Anim;

pub(crate) fn new() -> EnemyImpl {
    EnemyImpl {
        stats,
        update_animation,
    }
}

fn stats(enemy_type: EnemyType) -> Stats {
    let hitbox = match enemy_type {
        EnemyType::Octopus => Hitbox {
            x: 6,
            y: 14,
            w: 20,
            h: 13,
        },
        EnemyType::Blob => Hitbox {
            x: 3,
            y: 19,
            w: 26,
            h: 13,
        },
        EnemyType::Angel => Hitbox {
            x: 9,
            y: 14,
            w: 14,
            h: 9,
        },
        _ => Hitbox {
            x: 6,
            y: 17,
            w: 20,
            h: 14,
        },
    };
    Stats {
        speed: 16, // Pixel per second
        health: 3,
        strength: 1,
        melee: true,
        shoots: false,
        sings: false,
        tracks: true,
        flies: enemy_type == EnemyType::Angel || enemy_type == EnemyType::AngelMinion,
        hitbox,
    }
}

fn update_animation(enemy: &mut Enemy, walking: bool) {
    match enemy.status {
        Status::Dying { .. } => {
            enemy.sprite.maybe_set_anim(Anim::Die as usize);
        }
        Status::Idle => {
            let (mut anim, flip) = match enemy.facing {
                Direction::Left => (Anim::WalkRight as usize, true),
                Direction::Right => (Anim::WalkRight as usize, false),
                Direction::Up => (Anim::WalkUp as usize, false),
                Direction::Down => (Anim::WalkDown as usize, false),
            };
            if !walking {
                // Use the idle animation since we're not walking.
                anim = match enemy.facing {
                    Direction::Left | Direction::Right => Anim::IdleRight as usize,
                    Direction::Up => Anim::IdleUp as usize,
                    Direction::Down => Anim::IdleDown as usize,
                };
            }
            enemy.sprite.maybe_set_anim(anim);
            enemy.sprite.flip_h = flip;
        }
        Status::KnockedBack {
            direction: _,
            cooldown,
        } => {
            // Just started
            if cooldown == enemy::KNOCKBACK_COOLDOWN - 1 {
                let (anim, flip) = match enemy.facing {
                    Direction::Left => (Anim::DamageRight as usize, true),
                    Direction::Right => (Anim::DamageRight as usize, false),
                    Direction::Up => (Anim::DamageUp as usize, false),
                    Direction::Down => (Anim::DamageDown as usize, false),
                };
                enemy.sprite.set_anim(anim);
                enemy.sprite.flip_h = flip;
            }
        }
        _ => {}
    }
    enemy.sprite.update();
}
