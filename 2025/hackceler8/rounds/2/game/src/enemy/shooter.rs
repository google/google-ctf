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
        EnemyType::Archer => {
            arrow::new(state, vdp, /* keep_loaded= */ false)
        }
        _ => fireball::new(state, vdp, /* keep_loaded= */ false),
    }
}

pub fn get_projectile_start_offset(enemy_type: EnemyType, direction: Direction) -> (i16, i16) {
    // Adjust the projectile start position based on the sprites so the graphics look nicer.
    match enemy_type {
        EnemyType::Archer => match direction {
            Direction::Left => (11, 12),
            Direction::Right => (7, 12),
            Direction::Up => (10, 0),
            Direction::Down => (2, 10),
        },
        EnemyType::Flameboi => (4, 17),
        _ => (0, 0),
    }
}

fn stats(enemy_type: EnemyType) -> Stats {
    let hitbox = match enemy_type {
        EnemyType::Flameboi => Hitbox {
            x: 5,
            y: 20,
            w: 14,
            h: 12,
        },
        _ => Hitbox {
            x: 6,
            y: 12,
            w: 20,
            h: 20,
        },
    };
    Stats {
        speed: 16, // Pixel per second
        health: 3,
        strength: 1,
        melee: false,
        shoots: true,
        sings: false,
        tracks: false,
        flies: false,
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
        Status::Shooting { .. } => {
            let (anim, flip) = match enemy.facing {
                Direction::Left => (Anim::ShootRight as usize, true),
                Direction::Right => (Anim::ShootRight as usize, false),
                Direction::Up => (Anim::ShootUp as usize, false),
                Direction::Down => (Anim::ShootDown as usize, false),
            };
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
