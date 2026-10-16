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

use megahx8::*;

use super::Direction;
use super::Enemy;
use super::Hitbox;
use super::Stats;
use super::Status;
use crate::big_sprite::BigSprite;
use crate::enemy;
use crate::enemy::EnemyImpl;
use crate::res::enemies::EnemyType;
use crate::res::sprites::archer::Anim;
use crate::res::sprites::arrow;
use crate::res::sprites::fireball;
use crate::resource_state::State;

// Shoot every 120 frames (2s).
pub const SHOOT_FREQUENCY: u16 = 120;
// Go back to 60 frames (1s) after shooting.
pub const SHOOT_COOLDOWN: u8 = 60;
// Projectile appears 15 frames after shooting starts.
pub const PROJECTILE_DELAY: u8 = 15;

pub(crate) fn new() -> EnemyImpl {
    EnemyImpl {
        stats,
        update_animation,
    }
}

pub fn get_projectile_sprite(
    enemy_type: EnemyType,
    state: &mut State,
    vdp: &mut TargetVdp,
) -> BigSprite {
    match enemy_type {
        EnemyType::Archer | EnemyType::ArcherMiniboss => {
            arrow::new(
                state, vdp, /* singleton= */ false, /* keep_loaded= */ false,
            )
        }
        _ => fireball::new(
            state, vdp, /* singleton= */ false, /* keep_loaded= */ false,
        ),
    }
}

pub fn get_projectile_start_offset(enemy_type: EnemyType, direction: Direction) -> (i16, i16) {
    // Adjust the projectile start position based on the sprites so the graphics look nicer.
    match enemy_type {
        EnemyType::Archer | EnemyType::ArcherMiniboss => match direction {
            Direction::Left => (11, 12),
            _ => (7, 12),
        },
        EnemyType::Flameboi => (4, 17),
        _ => (0, 0),
    }
}

fn stats(enemy_type: EnemyType) -> Stats {
    let hitbox = match enemy_type {
        EnemyType::Flameboi | EnemyType::FlameboiMiniboss => Hitbox {
            x: 5,
            y: 0,
            w: 14,
            h: 32,
        },
        EnemyType::Goblin | EnemyType::GoblinMiniboss => Hitbox {
            x: 6,
            y: -1,
            w: 20,
            h: 32,
        },
        _ => Hitbox {
            x: 6,
            y: 0,
            w: 20,
            h: 32,
        },
    };
    Stats {
        speed: 16, // Pixel per second
        health: 3,
        strength: 3,
        melee: false,
        shoots: true,
        hitbox,
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
        Status::Shooting { .. } => {
            enemy.sprite.maybe_set_animation(Anim::Shoot as usize);
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
    }
    enemy.sprite.update();
}
