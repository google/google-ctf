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
use crate::res::sprites::siren::Anim;

// Start singing if the player is within 30 pixels.
const MIN_DISTANCE: i32 = 100;
// Player moves 1 px towards the singer every 2nd frame.
pub const LURE_EVERY_NTH_FRAME: u16 = 2;

pub(crate) fn new() -> EnemyImpl {
    EnemyImpl {
        stats,
        update_animation,
    }
}

pub fn within_singing_distance(enemy_hitbox: &Hitbox, player_hitbox: &Hitbox) -> bool {
    let enemy_center = enemy_hitbox.center();
    let player_center = player_hitbox.center();
    // i32 to avoid overflows during distance calc
    let dx = (player_center.0 - enemy_center.0) as i32;
    let dy = (player_center.1 - enemy_center.1) as i32;
    dx * dx + dy * dy <= MIN_DISTANCE * MIN_DISTANCE
}

fn stats(_: EnemyType) -> Stats {
    Stats {
        speed: 32,
        health: 3,
        strength: 1,
        melee: true,
        shoots: false,
        sings: true,
        tracks: false,
        flies: false,
        hitbox: Hitbox {
            x: 6,
            y: 14,
            w: 20,
            h: 18,
        },
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
        Status::Singing => {
            let (anim, flip) = match enemy.facing {
                Direction::Left => (Anim::SingRight as usize, true),
                Direction::Right => (Anim::SingRight as usize, false),
                Direction::Up => (Anim::SingUp as usize, false),
                Direction::Down => (Anim::SingDown as usize, false),
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
