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

use super::Enemy;
use super::Hitbox;
use super::Stats;
use crate::big_sprite::BigSprite;
use crate::data;
use crate::enemy;
use crate::enemy::EnemyImpl;
use crate::enemy::Status;
use crate::entity::*;
use crate::game::Ctx;
use crate::projectile::Trajectory;
use crate::res::enemies::EnemyType;
use crate::res::sprites::boss::Anim;
use crate::res::sprites::explosion as ExplosionSprite;
use crate::res::sprites::fireball;
use crate::resource_state::State;
use crate::Projectile;

pub(crate) fn new() -> EnemyImpl {
    EnemyImpl {
        stats,
        update_animation,
    }
}

fn stats(_enemy_type: EnemyType) -> Stats {
    Stats {
        speed: 16,
        health: 80,
        strength: 3,
        melee: true,
        shoots: false,
        hitbox: Hitbox {
            x: 8,
            y: 27,
            w: 46,
            h: 47,
        },
    }
}

fn update_animation(enemy: &mut Enemy, _walking: bool) {
    match enemy.status {
        Status::Dying { .. } => {
            enemy.sprite.maybe_set_animation(Anim::Die as usize);
        }
        Status::Idle => {
            enemy.sprite.maybe_set_animation(Anim::Idle as usize);
        }
        Status::Damaged { cooldown } => {
            // Just started
            if cooldown == enemy::DAMAGE_COOLDOWN - 1 {
                enemy.sprite.set_animation(Anim::Damage as usize);
            }
        }
        _ => {}
    }
    enemy.sprite.update();
}

pub enum AttackStatus {
    Idle { cooldown: u16 },
    Melee { trajectory: Trajectory, frame: u16 },
    Shoot { frame: u16 },
    Circle { frame: u16 },
}

/// Boss related enemy state data.
pub struct BossState {
    /// Explosions for the boss death sequence.
    explosion_sprites: [BigSprite; 2],
    /// The current attack of the boss (or Idle if it's not attacking).
    pub attack_status: AttackStatus,
    /// Position of the next attack from data::BOSS_ATTACKS
    attack_pos: usize,
}

const FRAMES_BETWEEN_ATTACKS: u16 = 100;

impl BossState {
    pub fn new(res_state: &mut State, vdp: &mut TargetVdp) -> BossState {
        let mut explosion_sprites = [
            ExplosionSprite::new(
                res_state, vdp, /* singleton= */ false, /* keep_loaded= */ false,
            ),
            ExplosionSprite::new(
                res_state, vdp, /* singleton= */ false, /* keep_loaded= */ false,
            ),
        ];
        for sprite in &mut explosion_sprites {
            sprite.set_animation(ExplosionSprite::Anim::Explode as usize);
        }
        BossState {
            explosion_sprites,
            attack_status: AttackStatus::Idle {
                cooldown: FRAMES_BETWEEN_ATTACKS,
            },
            attack_pos: 0,
        }
    }

    pub fn update(ctx: &mut Ctx) {
        if ctx.map.boss_state.is_none() {
            return;
        }
        let state = ctx.map.boss_state.as_mut().unwrap();

        let boss = ctx.map.enemies.iter_mut().find(|e| e.is_boss());
        if boss.is_none() {
            return;
        }
        let boss = boss.unwrap();

        for sprite in &mut state.explosion_sprites {
            sprite.update();
        }

        // Update explosion positions for the boss defeat sequence.
        if let Status::Dying { cooldown } = boss.status {
            let center = boss.hitbox().center();
            for (i, sprite) in state.explosion_sprites.iter_mut().enumerate() {
                // Start new explosions at random positions with a phase shift between the two sprites.
                let explosion_frame = cooldown as usize + 15 * i;
                if explosion_frame % 30 == 1 {
                    let (dx, dy) = data::EXPLOSION_OFFSETS[i][explosion_frame / 30];
                    sprite.set_position(center.0 - 8 + dx, center.1 - 8 + dy);
                    sprite.set_animation(ExplosionSprite::Anim::Explode as usize);
                }
            }
        }

        if !boss.is_alive() {
            return;
        }

        // Attacks last 2x as long after the boss is down to half its health.
        let duration_multiplier = if boss.health() > 40 { 1 } else { 2 };

        match &state.attack_status {
            AttackStatus::Idle { cooldown } => {
                if *cooldown == 0 {
                    let next_attack = data::BOSS_ATTACKS[state.attack_pos];
                    state.attack_pos = (state.attack_pos + 1) % data::BOSS_ATTACKS.len();

                    if next_attack == 0 {
                        let center = boss.hitbox().center();
                        let player_center = ctx.player.hitbox().center();
                        boss.orig_x = boss.x;
                        boss.orig_y = boss.y;
                        state.attack_status = AttackStatus::Melee {
                            trajectory: Trajectory::new(
                                boss.x,
                                boss.y,
                                player_center.0 - center.0,
                                player_center.1 - center.1,
                                /*speed=*/ 4,
                            ),
                            frame: 0,
                        };
                    } else if next_attack == 1 {
                        state.attack_status = AttackStatus::Shoot { frame: 0 };
                    } else if next_attack == 2 {
                        state.attack_status = AttackStatus::Circle { frame: 0 };
                    }
                } else {
                    state.attack_status = AttackStatus::Idle {
                        cooldown: cooldown - 1,
                    };
                }
            }
            AttackStatus::Melee {
                mut trajectory,
                mut frame,
            } => {
                if !trajectory.arrived_at_destination() {
                    let (new_x, new_y) = trajectory.update();
                    boss.set_position(new_x, new_y);
                } else {
                    frame += 1;
                    if frame == duration_multiplier * 50 {
                        trajectory = Trajectory::new(
                            boss.x,
                            boss.y,
                            boss.orig_x - boss.x,
                            boss.orig_y - boss.y,
                            /*speed=*/ 2,
                        );
                    } else if frame == 50 {
                        // Target the player a second time
                        let center = boss.hitbox().center();
                        let player_center = ctx.player.hitbox().center();
                        trajectory = Trajectory::new(
                            boss.x,
                            boss.y,
                            player_center.0 - center.0,
                            player_center.1 - center.1,
                            /*speed=*/ 4,
                        );
                    }
                }
                state.attack_status = if frame == duration_multiplier * 50 + 1 {
                    AttackStatus::Idle {
                        cooldown: FRAMES_BETWEEN_ATTACKS,
                    }
                } else {
                    AttackStatus::Melee {
                        trajectory: trajectory,
                        frame: frame,
                    }
                };
            }
            AttackStatus::Shoot { mut frame } => {
                frame += 1;

                if frame % 25 == 1 {
                    let center = boss.hitbox().center();
                    let offs_idx = if frame % 50 == 1 { 0 } else { 1 };
                    for (dx, dy) in data::BOSS_BULLET_OFFSETS[offs_idx] {
                        if dx == 0 && dy == 0 {
                            // Skip empty offset
                            continue;
                        }
                        let projectile = Projectile::new(
                            center.0 - 8,
                            center.1 + 8,
                            dx,
                            dy,
                            /*speed=*/ 4,
                            /*strength=*/ 6,
                            fireball::new(
                                &mut ctx.res_state,
                                &mut ctx.vdp,
                                /* singleton= */ false,
                                /* keep_loaded= */ false,
                            ),
                            /*is_player=*/ false,
                        );
                        if ctx.map.projectiles.push(projectile).is_err() {
                            warn!("Failed to load projectile, vector full?");
                        }
                    }
                }

                state.attack_status = if frame == duration_multiplier * 50 {
                    AttackStatus::Idle {
                        cooldown: FRAMES_BETWEEN_ATTACKS,
                    }
                } else {
                    AttackStatus::Shoot { frame: frame }
                }
            }
            AttackStatus::Circle { mut frame } => {
                frame += 1;
                state.attack_status = if frame == duration_multiplier * 100 {
                    AttackStatus::Idle {
                        cooldown: FRAMES_BETWEEN_ATTACKS,
                    }
                } else {
                    AttackStatus::Circle { frame: frame }
                }
            }
        }
    }

    pub fn render(
        &mut self,
        res_state: &mut State,
        vdp: &mut TargetVdp,
        renderer: &mut TargetRenderer,
    ) {
        for sprite in &mut self.explosion_sprites {
            sprite.render(res_state, vdp, renderer);
        }
    }
}
