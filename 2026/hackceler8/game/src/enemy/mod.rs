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

pub mod boss;
mod harmless;
mod melee;
mod shooter;

use crate::big_sprite::BigSprite;
use crate::entity::*;
use crate::game::Ctx;
use crate::res::enemies;
use crate::res::enemies::EnemyType;
use crate::resource_state::State;
use crate::walk::WalkData;
use crate::walk::WalkState;
use crate::Direction;
use crate::Player;
use crate::Projectile;

/// Stop damage status after 30 frames (0.5s)
pub const DAMAGE_COOLDOWN: u8 = 30;
/// Regular enemies disappear after death in 1s, the boss death
/// sequence takes longer.
pub const REGULAR_DEATH_COOLDOWN: u16 = 50;
pub const BOSS_DEATH_COOLDOWN: u16 = 210;

pub struct Stats {
    speed: i16,
    health: u16,
    strength: u16,
    melee: bool,
    shoots: bool,
    /// Hitbox relative to the sprite's x and y coordinates.
    hitbox: Hitbox,
}

/// Enemy properties parsed from the map that can override the
/// default properties.
pub struct EnemyProperties {
    pub id: u16,
    pub walk_data: &'static [WalkData],
    pub speed: Option<i16>,
    pub health: Option<u16>,
    pub strength: Option<u16>,
    pub invulnerable: bool,
    /// Flags the miniboss gives when defeated. Only applicable to minibosses.
    pub flags: Option<u16>,
}

impl Stats {
    fn apply_properities(mut self, properties: &EnemyProperties) -> Stats {
        // Override default stats with ones set on the map.
        if let Some(speed) = properties.speed {
            self.speed = speed;
        }
        if let Some(health) = properties.health {
            self.health = health;
        }
        if let Some(strength) = properties.strength {
            self.strength = strength;
        }
        self
    }
}

#[repr(C)]
pub struct Enemy {
    pub x: i16,
    pub y: i16,
    pub id: u16,
    pub facing: Direction,
    pub status: Status,
    stats: Stats,
    /// Flags the miniboss gives when defeated. Only applicable to minibosses.
    flags: u16,
    pub enemy_type: EnemyType,
    sprite: BigSprite,
    pub invulnerable: bool,
    walk_state: WalkState,
    enemy_impl: EnemyImpl,
}

/// Collection of enemy type-specific functions.
pub struct EnemyImpl {
    stats: fn(EnemyType) -> Stats,
    update_animation: fn(enemy: &mut Enemy, walked: bool),
}

#[cfg_attr(feature = "tests", derive(Debug))]
pub enum Status {
    Damaged { cooldown: u8 },
    Idle,
    Shooting { cooldown: u8 },
    Dying { cooldown: u16 },
}

impl Enemy {
    pub fn new(
        enemy_type: EnemyType,
        map_x: i16,
        map_y: i16,
        properties: &'static EnemyProperties,
        res_state: &mut State,
        vdp: &mut TargetVdp,
    ) -> Enemy {
        let enemy_impl = match enemy_type {
            EnemyType::Angel
            | EnemyType::AngelMiniboss
            | EnemyType::Blob
            | EnemyType::BlobMiniboss
            | EnemyType::Octopus
            | EnemyType::OctopusMiniboss
            | EnemyType::Orc
            | EnemyType::OrcMiniboss
            | EnemyType::OrcMinion => melee::new(),
            EnemyType::Archer
            | EnemyType::ArcherMiniboss
            | EnemyType::BossHand
            | EnemyType::Goblin
            | EnemyType::GoblinMiniboss
            | EnemyType::Flameboi
            | EnemyType::FlameboiMiniboss => shooter::new(),
            EnemyType::Rabbit | EnemyType::RabbitMiniboss => harmless::new(),
            EnemyType::Boss => boss::new(),
        };
        let stats = (enemy_impl.stats)(enemy_type).apply_properities(properties);
        let center = stats.hitbox.center();
        let sprite_x = map_x + 128 - center.0;
        let sprite_y = map_y + 128 - center.1;
        let mut sprite = enemies::sprite_init_fn(enemy_type)(
            res_state,
            vdp,
            // Bosses and minibosses only appear once.
            /* singleton= */
            properties.flags.is_some(),
            /* keep_loaded= */ false,
        );
        sprite.set_position(sprite_x, sprite_y);

        let mut enemy = Enemy {
            facing: Direction::Right,
            x: sprite_x,
            y: sprite_y,
            id: properties.id,
            sprite,
            status: Status::Idle,
            stats,
            invulnerable: properties.invulnerable,
            flags: properties.flags.unwrap_or(0),
            enemy_type,
            walk_state: WalkState::new(properties.walk_data),
            enemy_impl,
        };
        (enemy.enemy_impl.update_animation)(&mut enemy, /*walking*/ false);
        enemy
    }

    /// Runs an enemy tick. Returns whether the enemy has been defeated.
    pub fn update(ctx: &mut Ctx, enemy_id: usize) -> bool {
        let mut solved_map: Option<u8> = None;
        let mut won = false;
        let enemy = &mut ctx.map.enemies[enemy_id];
        let mut walking = false;

        match enemy.status {
            Status::Dying { mut cooldown } => {
                cooldown = cooldown + 1;
                if cooldown >= enemy.death_cooldown() {
                    if enemy.is_miniboss() && ctx.defeated_minibosses & enemy.enemy_type as u32 == 0
                    {
                        ctx.defeated_minibosses |= enemy.enemy_type as u32;
                        // Deferred to the tail block
                        // so the record lands before trigger_win ends
                        // the game on the boss.
                        solved_map = Some(crate::game::challenge_id(ctx.map.map_type));
                        if enemy.is_boss() {
                            won = true;
                        }
                    }
                }

                enemy.status = Status::Dying { cooldown };
            }
            Status::Idle => {
                let player = &mut ctx.player;
                // Follow predefined walk data.
                let (mut dx, mut dy) = enemy.walk_state.update();

                if dx != 0 {
                    walking = true;
                    enemy.face_dir(dx);
                } else {
                    enemy.face_player(player);
                }

                let mut speed_per_frame = enemy.stats.speed / 64;
                if speed_per_frame == 0 {
                    // Less than 1px per frame
                    // So instead we move 1px every N frames
                    let frame_per_pixel = 64 / enemy.stats.speed as u32;
                    if ctx.map.play_frame % frame_per_pixel == 0 {
                        speed_per_frame = 1;
                    }
                }
                if dx > speed_per_frame {
                    dx = speed_per_frame;
                } else if dx < -speed_per_frame {
                    dx = -speed_per_frame;
                }
                if dy > speed_per_frame {
                    dy = speed_per_frame;
                } else if dy < -speed_per_frame {
                    dy = -speed_per_frame;
                }
                enemy.move_relative(dx, dy);

                if enemy.stats.melee && enemy.hitbox().collides(&player.hitbox()) {
                    player.on_hit(enemy.facing, enemy.stats.strength);
                }

                if enemy.stats.shoots && ctx.map.play_frame % (shooter::SHOOT_FREQUENCY as u32) == 0
                {
                    enemy.face_player(player);
                    enemy.status = Status::Shooting {
                        cooldown: shooter::SHOOT_COOLDOWN,
                    };
                }
            }
            Status::Shooting { cooldown } => {
                if cooldown == shooter::SHOOT_COOLDOWN - shooter::PROJECTILE_DELAY {
                    let player = &mut ctx.player;
                    let (offs_x, offs_y) =
                        shooter::get_projectile_start_offset(enemy.enemy_type, enemy.facing);
                    let projectile = Projectile::new(
                        enemy.x + offs_x,
                        enemy.y + offs_y,
                        player.x - enemy.x,
                        player.y - enemy.y,
                        /*speed=*/ 2,
                        enemy.stats.strength,
                        shooter::get_projectile_sprite(
                            enemy.enemy_type,
                            &mut ctx.res_state,
                            &mut ctx.vdp,
                        ),
                        /*is_player=*/ false,
                    );
                    if ctx.map.projectiles.push(projectile).is_err() {
                        warn!("Failed to load projectile, vector full?");
                    }
                }

                enemy.status = if cooldown > 0 {
                    Status::Shooting {
                        cooldown: cooldown - 1,
                    }
                } else {
                    Status::Idle
                };
            }
            Status::Damaged { cooldown } => {
                enemy.status = if cooldown > 0 {
                    Status::Damaged {
                        cooldown: cooldown - 1,
                    }
                } else {
                    Status::Idle
                };
            }
        }

        enemy.update_animation(walking);
        let defeated = matches!(enemy.status, Status::Dying { .. });

        if let Some(challenge_id) = solved_map {
            ctx.portal.mark_challenge_solved(challenge_id);
            ctx.recompute_captured_flags();
        }
        if won {
            ctx.trigger_win();
        }

        defeated
    }

    pub fn kill(&mut self) {
        if !matches!(self.status, Status::Dying { .. }) {
            self.status = Status::Dying { cooldown: 0 };
        }
    }

    pub fn on_hit(&mut self, damage: u16) {
        if !self.is_alive() || self.invulnerable {
            return;
        }
        if self.stats.health <= damage {
            self.stats.health = 0;
            self.status = Status::Dying { cooldown: 0 };
            return;
        }
        self.stats.health -= damage;
        self.status = Status::Damaged {
            cooldown: DAMAGE_COOLDOWN,
        };
    }

    pub fn is_alive(&self) -> bool {
        !matches!(self.status, Status::Dying { .. })
    }

    /// Returns true if the enemy should be unloaded from memory.
    /// This mean the entity is fully dead and not rendered anymore.
    pub fn should_unload(&self) -> bool {
        match self.status {
            Status::Dying { cooldown } => cooldown == self.death_cooldown(),
            _ => false,
        }
    }

    /// Amount of ticks until this enemy should finish its death sequence and be unloaded.
    fn death_cooldown(&self) -> u16 {
        if self.is_boss() {
            BOSS_DEATH_COOLDOWN
        } else {
            REGULAR_DEATH_COOLDOWN
        }
    }

    /// Enemies that return flags are minibosses. Only one of each EnemyType can be a miniboss.
    fn is_miniboss(&self) -> bool {
        self.flags > 0
    }

    pub fn is_boss(&self) -> bool {
        self.enemy_type == EnemyType::Boss
    }

    fn face_player(&mut self, player: &Player) {
        self.face_dir(player.x - self.x);
    }

    fn face_dir(&mut self, dx: i16) {
        if dx < 0 {
            self.facing = Direction::Left
        } else if dx > 0 {
            self.facing = Direction::Right
        };
    }

    fn update_animation(&mut self, walking: bool) {
        (self.enemy_impl.update_animation)(self, walking);
    }

    pub fn health(&self) -> u16 {
        self.stats.health
    }
}

impl Entity for Enemy {
    fn hitbox(&self) -> Hitbox {
        let rh = &self.stats.hitbox;
        Hitbox {
            x: self.x + rh.x,
            y: self.y + rh.y,
            w: rh.w,
            h: rh.h,
        }
    }

    fn render(
        &mut self,
        res_state: &mut State,
        vdp: &mut TargetVdp,
        renderer: &mut TargetRenderer,
    ) {
        self.sprite.render(res_state, vdp, renderer);
    }

    #[expect(clippy::cast_sign_loss)]
    /// Set the absolute position of a sprite on the screen.
    fn set_position(&mut self, x: i16, y: i16) {
        self.x = x;
        self.y = y;
        self.sprite.set_position(x, y);
    }

    fn move_relative(&mut self, dx: i16, dy: i16) {
        self.set_position(self.x + dx, self.y + dy);
    }
}
