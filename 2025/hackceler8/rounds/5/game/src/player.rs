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
use resources::MapTileAttribute;

use crate::big_sprite::BigSprite;
use crate::data;
use crate::entity::*;
use crate::game::Ctx;
use crate::get_map;
use crate::physics;
use crate::res::items::ItemType;
use crate::res::sprites::player_base as PlayerSprite;
use crate::resource_state::State;
use crate::Direction;

const DEFAULT_MAX_HEALTH: u16 = 3;
pub const SPEED_SCALE_FACTOR: i16 = 64;

/// macro to get the current map from [`Ctx`]
#[macro_export]
macro_rules! get_player {
    ($ctx:ident, $player_id:expr) => {
        (&$ctx.players[$player_id])
    };
}

/// macro to get the current map from ctx, mut
#[macro_export]
macro_rules! get_player_mut {
    ($ctx:ident, $player_id:expr) => {
        (&mut $ctx.players[$player_id])
    };
}

pub struct Player {
    id: ID,
    pub x: i16,
    pub y: i16,
    pub prev_x: i16,
    pub prev_y: i16,
    facing: Direction,

    sprite: BigSprite,
    hat_sprite: BigSprite,
    pub status: Status,
    moving: bool,

    pub active: bool,

    pub health: u16,
    pub max_health: u16,
    pub speed: i16,
    pub strength: u16,
}

#[derive(Copy, Clone)]
pub enum ID {
    P1,
    P2,
    P3,
    P4,
}

#[derive(Copy, Clone, PartialEq)]
pub enum Status {
    // Not doing anything special (= moving, standing)
    Idle,
    // Cooldown in frames
    Attacking { cooldown: u8 },
    KnockedBack { direction: (i16, i16), cooldown: u8 },

    Dying { cooldown: u8, speed: Option<i16> },
    Dead,
}

impl Player {
    pub fn new(id: ID, team_id: u8, res_state: &mut State, vdp: &mut TargetVdp) -> Self {
        Self {
            id,
            // Coords are overwritten after initialization.
            x: 0,
            y: 0,
            prev_x: 0,
            prev_y: 0,
            facing: Direction::Down,
            sprite: data::get_player_sprite(team_id, res_state, vdp),
            hat_sprite: data::get_hat_sprite(team_id, res_state, vdp),
            active: matches!(id, ID::P1),
            health: DEFAULT_MAX_HEALTH,
            max_health: DEFAULT_MAX_HEALTH,
            speed: SPEED_SCALE_FACTOR,
            strength: 1,
            status: Status::Idle,
            moving: false,
        }
    }

    pub fn is_alive(&self) -> bool {
        !matches!(self.status, Status::Dead | Status::Dying { .. })
    }

    pub fn is_dead(&self) -> bool {
        matches!(self.status, Status::Dead)
    }

    pub fn is_active(&self) -> bool {
        self.is_alive() && self.active
    }

    pub fn kill(&mut self, falling: bool) {
        if self.is_alive() {
            self.health = 0;
            self.status = Status::Dying {
                cooldown: 120,
                speed: if falling { None } else { Some(5) },
            };
        }
    }

    pub fn set_idle(&mut self) {
        self.status = Status::Idle;
    }

    pub fn reset(&mut self) {
        self.active = matches!(self.id, ID::P1); // Only P1 starts out active.
        self.status = Status::Idle;
        self.health = DEFAULT_MAX_HEALTH;
        self.max_health = DEFAULT_MAX_HEALTH;
        self.speed = SPEED_SCALE_FACTOR;
        self.strength = 1;
        self.facing = Direction::Down;
        self.sprite.set_anim(PlayerSprite::Anim::IdleDown as usize);
        self.hat_sprite
            .set_anim(data::get_player_hat_anim(self.status, self.id) as usize);
        self.sprite.flip_h = false;
        self.sprite.flip_v = false;
    }

    pub fn on_hit(&mut self, direction: (i16, i16), damage: u16) {
        if !self.is_alive() {
            return;
        }
        if let Status::KnockedBack { .. } = self.status {
            return;
        }
        if self.health <= damage {
            self.health = 0;
            self.kill(false)
        } else {
            self.health -= damage;
            self.status = Status::KnockedBack {
                direction,
                cooldown: 30,
            };
            let (anim, flip) = if direction.0.abs() > direction.1.abs() {
                (PlayerSprite::Anim::DamageRight as usize, direction.0 < 0)
            } else if direction.1 > 0 {
                (PlayerSprite::Anim::DamageDown as usize, false)
            } else {
                (PlayerSprite::Anim::DamageUp as usize, false)
            };
            self.sprite.set_anim(anim);
            self.hat_sprite
                .set_anim(data::get_player_hat_anim(self.status, self.id) as usize);
            self.sprite.flip_h = flip;
        }
    }

    pub fn update(ctx: &mut Ctx, player_id: usize) -> Option<(i16, i16)> {
        let frame = ctx.frame;

        let input = &mut ctx.controller.controller_state(player_id);

        let enemies = &mut ctx.world.enemies;
        let doors = &mut ctx.world.doors;
        let doors_opened = &mut ctx.world.doors_opened;
        let inventory = &mut ctx.world.inventory;

        // Spawn newly active players next to another active player.
        // Computed before get_player_mut to avoid double mutable borrows.
        let mut new_player_pos = None;
        if let Some(input) = input {
            if !get_player!(ctx, player_id).active && input.just_pressed(Button::Start) {
                for player in &ctx.players {
                    if player.active && player.is_alive() {
                        new_player_pos = Some((player.x, player.y));
                        break;
                    }
                }
            }
        }

        let player = get_player_mut!(ctx, player_id);
        let map = get_map!(ctx);
        let mut hits = None;

        if let Some(pos) = new_player_pos {
            player.set_position(pos.0, pos.1);
            player.active = true;
        }

        if !player.active {
            return None;
        }

        if player.is_alive() {
            player.prev_x = player.x;
            player.prev_y = player.y;
        }

        match player.status {
            Status::Dead => {}
            Status::Dying {
                cooldown,
                mut speed,
            } => {
                if let Some(speed) = speed.as_mut() {
                    let mut x = player.x;
                    if cooldown % 2 == 0 {
                        x -= 1;
                    }
                    player.set_position(x, player.y - *speed);
                    if *speed > -5 && cooldown % 4 == 0 {
                        *speed -= 1;
                    }
                }
                player.status = if player.health > 0 {
                    Status::Idle
                } else if cooldown > 0 {
                    Status::Dying {
                        cooldown: cooldown - 1,
                        speed,
                    }
                } else {
                    Status::Dead
                };
                player.sprite.maybe_set_anim(match speed {
                    None => PlayerSprite::Anim::Fall,
                    Some(_) => PlayerSprite::Anim::Die,
                } as usize);
                let flipv = match speed {
                    None => false,
                    Some(s) if s < 0 => true,
                    _ => false,
                };
                let fliph = match speed {
                    None => false,
                    Some(_) => frame & 32 > 0,
                };
                player.sprite.flip_v = flipv;
                player.sprite.flip_h = fliph;
            }
            Status::Idle => {
                let mut dir = (0i16, 0i16);
                if let Some(input) = input {
                    let scaled_speed = Self::scale_speed(player.speed, frame);
                    if input.is_pressed(Button::Up) {
                        dir.1 = -1 * scaled_speed;
                        player.facing = Direction::Up;
                    }
                    if input.is_pressed(Button::Down) {
                        dir.1 = scaled_speed;
                        player.facing = Direction::Down;
                    }
                    if input.is_pressed(Button::Left) {
                        dir.0 = -1 * scaled_speed;
                        player.facing = Direction::Left;
                    }
                    if input.is_pressed(Button::Right) {
                        dir.0 = scaled_speed;
                        player.facing = Direction::Right;
                    }
                    if input.just_pressed(Button::A) {
                        player.status = Status::Attacking { cooldown: 20 };
                        // Hit enemies
                        let (dx, dy) = match player.facing {
                            Direction::Right => (1, 0),
                            Direction::Left => (-1, 0),
                            Direction::Up => (0, -1),
                            Direction::Down => (0, 1),
                        };
                        let hitbox = player.hitbox();
                        let attack_hitbox = Hitbox {
                            x: hitbox.x + 10 * dx,
                            y: hitbox.y + 10 * dy,
                            w: hitbox.w,
                            h: hitbox.h,
                        };
                        for enemy in enemies {
                            if attack_hitbox.collides(&enemy.hitbox()) {
                                enemy.on_hit((dx * 60, dy * 60), player.strength);
                            }
                        }
                    }
                    if input.just_pressed(Button::B) && inventory.contains(ItemType::Key) {
                        // Open a nearby door.
                        let interaction_hitbox = player.hitbox().expand(5);
                        for door in doors.iter_mut() {
                            if !door.open && interaction_hitbox.collides(&door.hitbox()) {
                                door.open();
                                doors_opened.set(door.id);
                                inventory.remove(ItemType::Key);
                                break;
                            }
                        }
                    }
                    if input.just_pressed(Button::B) && inventory.contains(ItemType::InvisibleKey) {
                        // Open a nearby door.
                        let interaction_hitbox = player.hitbox().expand(5);
                        for door in doors.iter_mut() {
                            if !door.open && interaction_hitbox.collides(&door.hitbox()) {
                                door.open();
                                doors_opened.set(door.id);
                                inventory.remove(ItemType::InvisibleKey);
                                break;
                            }
                        }
                    }
                }

                player.moving = dir.0 != 0 || dir.1 != 0;
                hits = Some(physics::try_move(
                    player,
                    map,
                    &ctx.world.doors,
                    dir.0,
                    dir.1,
                ));

                let anim = match (player.facing, player.moving) {
                    (Direction::Right | Direction::Left, false) => PlayerSprite::Anim::IdleRight,
                    (Direction::Right | Direction::Left, true) => PlayerSprite::Anim::WalkRight,
                    (Direction::Up, false) => PlayerSprite::Anim::IdleUp,
                    (Direction::Up, true) => PlayerSprite::Anim::WalkUp,
                    (Direction::Down, false) => PlayerSprite::Anim::IdleDown,
                    (Direction::Down, true) => PlayerSprite::Anim::WalkDown,
                };

                player.sprite.maybe_set_anim(anim as usize);
                player.sprite.flip_v = false;
                player.sprite.flip_h = matches!(player.facing, Direction::Left);
            }
            Status::KnockedBack {
                direction,
                cooldown,
            } => {
                if cooldown > 20 {
                    hits = Some(physics::try_move(
                        player,
                        map,
                        &ctx.world.doors,
                        direction.0 / 60,
                        direction.1 / 60,
                    ));
                }
                player.sprite.x = player.x as u16;
                player.sprite.y = player.y as u16;
                player.status = if cooldown > 0 {
                    Status::KnockedBack {
                        direction,
                        cooldown: cooldown - 1,
                    }
                } else {
                    Status::Idle
                };
            }
            Status::Attacking { cooldown } => {
                player.status = if cooldown > 0 {
                    Status::Attacking {
                        cooldown: cooldown - 1,
                    }
                } else {
                    Status::Idle
                };
                let anim = match player.facing {
                    Direction::Right | Direction::Left => PlayerSprite::Anim::AttackRight,
                    Direction::Up => PlayerSprite::Anim::AttackUp,
                    Direction::Down => PlayerSprite::Anim::AttackDown,
                };
                player.sprite.maybe_set_anim(anim as usize);
                player.sprite.flip_h = matches!(player.facing, Direction::Left);
            }
        }
        player
            .hat_sprite
            .maybe_set_anim(data::get_player_hat_anim(player.status, player.id) as usize);

        if player.is_active() {
            if let Some(hits) = &hits {
                if hits.touches_tile(MapTileAttribute::Entrance) {
                    return Some((player.prev_x, player.prev_y));
                }
                if hits.touches_tile(MapTileAttribute::Spike) {
                    player.kill(false);
                }
                if hits.immersed_in_tile(MapTileAttribute::Hole) {
                    player.kill(true);
                }
            }
        }

        player.sprite.update();
        player.hat_sprite.update();
        player.update_hat_sprite_position();
        None
    }

    /// Preload all sprites that must always be loaded.
    pub fn preload_persistent_sprites(team_id: u8, res_state: &mut State, vdp: &mut TargetVdp) {
        data::get_player_sprite(team_id, res_state, vdp);
        data::get_hat_sprite(team_id, res_state, vdp);
    }

    /// Whether the level reset button combo (A+B+C) has been pressed.
    pub fn reset_pressed(ctx: &mut Ctx) -> bool {
        for p in 0..ctx.players.len() {
            if !ctx.players[p].active {
                continue;
            }
            if let Some(input) = ctx.controller.controller_state(p) {
                if (input.just_pressed(Button::A)
                    || input.just_pressed(Button::B)
                    || input.just_pressed(Button::C))
                    && input.is_pressed(Button::A)
                    && input.is_pressed(Button::B)
                    && input.is_pressed(Button::C)
                {
                    return true;
                }
            }
        }
        false
    }

    fn update_hat_sprite_position(&mut self) {
        let (dx, dy) = data::get_player_hat_position(self.status, self.facing);
        let center = self.hitbox().center();
        self.hat_sprite.set_position(center.0 + dx, center.1 + dy);
    }

    /// Scales player speed
    /// Takes raw speed value and current frame
    /// Returns distance in pixels player should move this frame
    fn scale_speed(speed: i16, frame: u16) -> i16 {
        let abs_scaled_speed =
            i16::try_from(Self::scale_abs_speed(speed.unsigned_abs(), frame)).unwrap();
        if speed < 0 {
            -abs_scaled_speed
        } else {
            abs_scaled_speed
        }
    }

    fn scale_abs_speed(speed: u16, frame: u16) -> u16 {
        // Scaled speed in whole pixels / frame
        let scaled_speed = speed / (SPEED_SCALE_FACTOR as u16);
        // Remainder = fixed point fractional part of the speed
        let fract_speed = speed % (SPEED_SCALE_FACTOR as u16);
        if fract_speed != 0 {
            // Instead of keeping the fractional part of the location, we move an
            // additional whole pixel each (1 / fractional_speed) frames.
            // This is equivalent to moving when:
            //   floor(frame * fractional_speed) > floor((frame - 1) * fractional_speed)
            // for 0 < fractional_speed < 1 this is equivalent to:
            //   frac(frame * fractional_speed) < fractional_speed
            if frame.wrapping_mul(fract_speed) % (SPEED_SCALE_FACTOR as u16) < fract_speed {
                return scaled_speed + 1;
            }
        }
        scaled_speed
    }
}

impl Entity for Player {
    fn hitbox(&self) -> Hitbox {
        Hitbox {
            x: self.x + 2,
            y: self.y + 11,
            w: 12,
            h: 8,
        }
    }

    fn render(&mut self, renderer: &mut TargetRenderer) {
        if !self.active || self.is_dead() {
            return;
        }
        if self.is_alive() {
            self.hat_sprite.render(renderer);
        }
        self.sprite.render(renderer);
    }

    fn set_position(&mut self, x: i16, y: i16) {
        self.x = x;
        self.y = y;
        self.sprite.set_position(x, y);
        self.update_hat_sprite_position();
    }

    fn move_relative(&mut self, dx: i16, dy: i16) {
        self.set_position(self.x + dx, self.y + dy);
    }
}
