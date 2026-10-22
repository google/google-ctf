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
use resources::MapTileAttribute;

use crate::big_sprite::BigSprite;
use crate::entity::*;
use crate::fader::fade_palette;
use crate::fader::FadeColor;
use crate::game::Ctx;
use crate::get_map_data;
use crate::map::Map;
use crate::map::SCREEN_HEIGHT;
use crate::map::SCREEN_WIDTH;
use crate::physics;
use crate::res::items::ItemType;
use crate::res::maps::MapType;
use crate::res::palettes;
use crate::res::sprites::player as PlayerSprite;
use crate::res::sprites::player_explosion as PlayerExplosionSprite;
use crate::res::sprites::player_melee as PlayerMeleeSprite;
use crate::res::sprites::player_sword as PlayerSwordSprite;
use crate::resource_state::State;
use crate::weapon::WeaponType;
use crate::Direction;

const DEFAULT_MAX_HEALTH: u16 = 10;
pub const SPEED_SCALE_FACTOR: i16 = 64;

/// Jump speed - 4 px per frame
const JUMP_SPEED: i16 = 4 * SPEED_SCALE_FACTOR;
/// Deceleration per frame - Start falling down after ~1s.
const GRAVITY: i16 = 8;
/// Speed for sliding down walls - 0.5px per frame
const SLIDE_SPEED: i16 = 32;
/// Dash speed and duration - 3 px per frame
const DASH_SPEED: i16 = 3 * SPEED_SCALE_FACTOR;
const DASH_DURATION_FRAMES: u16 = 40;
const AIR_DASH_DURATION_FRAMES: u16 = DASH_DURATION_FRAMES;
/// The duration of the death sequence.
const DEATH_DURATION_FRAMES: u8 = 120;
/// The frame at which death sequence explosions should appear.
const DEATH_EXPLOSION_FRAME: u8 = 10;
/// The melee attack frame at which a weapon's ability should be triggered
/// (e.g. shooting a projectile during saber slashes).
const MELEE_TRIGGER_FRAME: u8 = 10;
const INVULNERABILITY_DURATION_FRAMES: u16 = 75;

pub struct Player {
    pub x: i16,
    pub y: i16,
    pub prev_x: i16,
    pub prev_y: i16,
    pub player_type: PlayerType,
    pub weapon: WeaponType,
    pub h_speed: i16,

    pub health: u16,
    pub max_health: u16,
    pub speed: i16,
    /// Whether the player can air dash. Set to false once the player has already air dashed in this jump.
    air_dash_available: bool,
    /// Whether the player is currently air dashing (gravity paused, horizontal lock).
    is_air_dashing: bool,

    /// Whether the player is standing on a solid platform.
    pub on_ground: bool,
    /// Direction of a wall jump.
    /// Set when the player starts sliding down a wall and cleared once the jump ends.
    wall_jump_direction: Option<Direction>,
    /// The amount of time left from a dash. 0 if the player is currently not dashing.
    dash_timer: u16,
    /// Timer for registering double tapping of the move button.
    /// When the move button is double tapped the player starts dashing.
    double_tap_timer: u16,
    pub shoot_cooldown: u8,
    /// Whether the player can double jump. Set to false once the player has already jumped in the air once.
    double_jump_available: bool,
    pub charge_timer: u16,
    facing: Direction,

    pub sprite: BigSprite,
    weapon_sprite: Option<BigSprite>,
    /// Explosion sprites that appear during the player death sequence.
    explosion_sprites: [Option<BigSprite>; 8],
    /// Enemies hit with the melee attacks during the current attack.
    /// Used to ensure enemies are only hit once per attack.
    pub enemies_hit: u32,
    pub status: Status,

    /// Used to track invulnerability frames after taking damage.
    pub invulnerability_timer: u16,
    /// Speed of slipping on the ground on the Arctic stage.
    slip_speed: i16,
    /// Active player sprite palette in CRAM.
    pub palette: [u16; 16],
}

#[cfg_attr(feature = "tests", derive(Debug))]
#[derive(Copy, Clone, PartialEq)]
pub enum Status {
    // Not doing anything special (= moving, standing)
    Idle,
    // Beaming down into the stage.
    // The player sprite starts at the top of the screen (sprite_y = 0)
    // and beams to its actual spawn location.
    BeamingIn { sprite_y: i16 },
    // Cooldown in frames
    Attacking { cooldown: u8 },
    KnockedBack { direction: Direction, cooldown: u8 },
    Dying { cooldown: u8 },
    Dead,
}

#[derive(Copy, Clone, PartialEq)]
pub enum PlayerType {
    Shooter, // This player can only shoot bullets
    Melee,   // This player can only perform melee attacks
}

impl Player {
    pub fn new(player_type: PlayerType, res_state: &mut State, vdp: &mut TargetVdp) -> Self {
        let weapon = if player_type == PlayerType::Shooter {
            WeaponType::Gun
        } else {
            WeaponType::Sword
        };

        Self {
            player_type,
            weapon,
            // Coords are overwritten after initialization.
            x: 0,
            y: 0,
            prev_x: 0,
            prev_y: 0,
            h_speed: 0,
            on_ground: true,
            wall_jump_direction: None,
            dash_timer: 0,
            double_tap_timer: 0,
            double_jump_available: true,
            air_dash_available: true,
            is_air_dashing: false,
            facing: Direction::Right,
            sprite: get_sprite(player_type, res_state, vdp),
            weapon_sprite: weapon.get_sprite(res_state, vdp),
            explosion_sprites: [const { None }; 8],
            health: DEFAULT_MAX_HEALTH,
            max_health: DEFAULT_MAX_HEALTH,
            speed: SPEED_SCALE_FACTOR,
            enemies_hit: 0,
            status: Status::BeamingIn { sprite_y: 0 },
            shoot_cooldown: 0,
            charge_timer: 0,
            invulnerability_timer: 0,
            slip_speed: 0,
            palette: [0; 16],
        }
    }

    pub fn is_alive(&self) -> bool {
        !matches!(self.status, Status::Dead | Status::Dying { .. })
    }

    pub fn is_dead(&self) -> bool {
        matches!(self.status, Status::Dead)
    }

    pub fn is_active(&self) -> bool {
        !self.is_dead()
    }

    pub fn is_sliding_down_wall(&self) -> bool {
        self.wall_jump_direction.is_some() && self.h_speed > 0
    }

    fn is_dashing(&self) -> bool {
        self.dash_timer > 0
    }

    pub fn kill(&mut self) {
        if self.is_alive() {
            self.health = 0;
            self.status = Status::Dying {
                cooldown: DEATH_DURATION_FRAMES,
            };
        }
    }

    pub fn reset(&mut self) {
        self.status = Status::BeamingIn { sprite_y: 0 };
        self.h_speed = 0;
        self.on_ground = true;
        self.dash_timer = 0;
        self.double_jump_available = true;
        self.air_dash_available = true;
        self.is_air_dashing = false;
        self.health = DEFAULT_MAX_HEALTH;
        self.max_health = DEFAULT_MAX_HEALTH;
        self.speed = SPEED_SCALE_FACTOR;
        self.facing = Direction::Right;
        self.sprite.set_animation(PlayerSprite::Anim::Beam as usize);
        self.sprite.flip_h = false;
        self.shoot_cooldown = 0;
        self.charge_timer = 0;
        self.invulnerability_timer = 0;
        self.slip_speed = 0;
        self.palette = palettes::get_palette(Palette::A, self.palette_type());
    }

    pub fn on_hit(&mut self, direction: Direction, damage: u16) {
        #[cfg(feature = "god_mode")]
        return;

        if !self.is_alive() {
            return;
        }
        if let Status::KnockedBack { .. } = self.status {
            return;
        }
        if self.invulnerability_timer > 0 {
            return;
        }

        self.is_air_dashing = false;
        self.dash_timer = 0;
        self.slip_speed = 0;

        if self.health <= damage {
            self.health = 0;
            self.kill()
        } else {
            self.health -= damage;
            self.status = Status::KnockedBack {
                direction,
                cooldown: 30,
            };
            self.dash_timer = 0;
            self.invulnerability_timer = INVULNERABILITY_DURATION_FRAMES;
            self.sprite
                .set_animation(PlayerSprite::Anim::Damage as usize);
        }
    }

    pub fn update(ctx: &mut Ctx) {
        let frame = ctx.map.play_frame;
        let input = &mut ctx.controller.controller_state(0);

        let enemies = &mut ctx.map.enemies;
        let doors = &mut ctx.map.doors;
        let doors_unlocked = &mut ctx.map.doors_unlocked;
        let doors_locked = &mut ctx.map.doors_locked;
        let inventory = &mut ctx.map.inventory;

        // Whether the weapon's on_attack or on_hit function should be triggered
        // at the end on a certain enemy.
        // We track this in separate vars instead of calling the functions directly
        // to avoid double mut borrows.
        let mut trigger_attack = false;
        let mut enemies_to_hit = 0;
        let weapon = ctx.player.weapon;

        let player = &mut ctx.player;
        let map = get_map_data!(ctx);
        let mut hits = None;

        if player.invulnerability_timer > 0 {
            player.invulnerability_timer -= 1;
        }

        if player.is_alive() {
            player.prev_x = player.x;
            player.prev_y = player.y;
        }

        match player.status {
            Status::Dead => {}
            Status::Dying { cooldown } => {
                // Set up explosion sprites for death sequence.
                if cooldown == DEATH_DURATION_FRAMES - DEATH_EXPLOSION_FRAME {
                    let center = player.hitbox().center();
                    for i in 0..4 {
                        let mut sprite = get_explosion_sprite(
                            player.player_type,
                            &mut ctx.res_state,
                            &mut ctx.vdp,
                        );
                        sprite.set_position(center.0 - 8, center.1 - 8);
                        sprite.set_animation(PlayerExplosionSprite::Anim::Explode as usize);
                        player.explosion_sprites[i] = Some(sprite);
                    }
                } else if cooldown == DEATH_DURATION_FRAMES - DEATH_EXPLOSION_FRAME - 20 {
                    // Second batch of sprites coming a bit later.
                    let center = player.hitbox().center();
                    for i in 4..8 {
                        let mut sprite = get_explosion_sprite(
                            player.player_type,
                            &mut ctx.res_state,
                            &mut ctx.vdp,
                        );
                        sprite.set_position(center.0 - 8, center.1 - 8);
                        sprite.set_animation(PlayerExplosionSprite::Anim::Explode as usize);
                        player.explosion_sprites[i] = Some(sprite);
                    }
                }

                player.status = if cooldown > 0 {
                    Status::Dying {
                        cooldown: cooldown - 1,
                    }
                } else {
                    Status::Dead
                };
                player
                    .sprite
                    .maybe_set_animation(PlayerSprite::Anim::Die as usize);
            }
            Status::BeamingIn { mut sprite_y } => {
                if sprite_y < player.y {
                    if sprite_y == 0 {
                        player.move_to_ground(&ctx.map);
                    }

                    player
                        .sprite
                        .maybe_set_animation(PlayerSprite::Anim::Beam as usize);

                    sprite_y = (sprite_y + 4).min(player.y);
                    player.status = Status::BeamingIn { sprite_y };
                } else {
                    player
                        .sprite
                        .maybe_set_animation(PlayerSprite::Anim::BeamStop as usize);
                    if player.sprite.is_animation_finished() {
                        player.status = Status::Idle;
                    }
                }
                // Call set_position to update the sprite's horizontal position.
                player.set_position(player.x, player.y);
            }
            Status::Idle => {
                let mut move_x = 0i16;
                let mut walking = false;
                let mut jump_pressed = false;
                let mut keep_dashing = false;
                let prev_facing = player.facing;
                let prev_sliding_down_wall = player.is_sliding_down_wall();

                if player.weapon == WeaponType::Gun {
                    // Projectile charging "animation"
                    // Flicker = +2 to brightness every 8 frames, for 8 frames
                    let flicker = ((frame as u16 >> 3) % 2) * 2;
                    let fade_amount = (player.charge_timer >> 2).min(8 + flicker);
                    player.palette = fade_palette(
                        &palettes::get_palette(Palette::A, player.palette_type()),
                        FadeColor::White,
                        fade_amount,
                    );
                    ctx.vdp.set_palette(Palette::A, &player.palette);
                }

                if let Some(input) = input {
                    jump_pressed = input.is_pressed(Button::Up);
                    keep_dashing = input.is_pressed(Button::C)
                        || input.is_pressed(Button::Left)
                        || input.is_pressed(Button::Right);
                    if input.just_pressed(Button::Up) {
                        if player.on_ground || player.is_sliding_down_wall() {
                            player.h_speed = -JUMP_SPEED;
                        } else if player.double_jump_available
                            && inventory.contains(ItemType::Doublejump)
                        {
                            player.h_speed = -JUMP_SPEED;
                            player.double_jump_available = false;
                            player.air_dash_available = false;
                            player.dash_timer = 0;
                            player.is_air_dashing = false;
                            player
                                .sprite
                                .set_animation(PlayerSprite::Anim::JumpUp as usize);
                        }
                    }

                    let move_just_pressed_dir = if input.just_pressed(Button::Left) {
                        Some(Direction::Left)
                    } else if input.just_pressed(Button::Right) {
                        Some(Direction::Right)
                    } else {
                        None
                    };
                    let is_double_tap = player.double_tap_timer > 0
                        && move_just_pressed_dir.is_some()
                        && move_just_pressed_dir == Some(player.facing);

                    // Dash if the dash button is pressed or if the move button is tapped twice.
                    if input.just_pressed(Button::C) || is_double_tap {
                        if !player.is_dashing() {
                            if (player.on_ground || player.is_sliding_down_wall())
                                && inventory.contains(ItemType::Dash)
                            {
                                player.dash_timer = DASH_DURATION_FRAMES;
                                player.double_tap_timer = 0;
                            } else {
                                if !player.on_ground
                                    && player.air_dash_available
                                    && inventory.contains(ItemType::Airdash)
                                {
                                    player.dash_timer = AIR_DASH_DURATION_FRAMES;
                                    player.double_tap_timer = 0;
                                    player.air_dash_available = false;
                                    player.double_jump_available = false;
                                    player.is_air_dashing = true;
                                    player.h_speed = 0;
                                }
                            }
                        }
                    } else if move_just_pressed_dir.is_some() {
                        // Tap again within 0.5s to start dashing.
                        player.double_tap_timer = 30;
                    }

                    let mut speed_x = 0;
                    if input.is_pressed(Button::Left) {
                        speed_x = -1 * player.speed;
                        walking = true;
                        player.facing = Direction::Left;
                    }
                    if input.is_pressed(Button::Right) {
                        speed_x = player.speed;
                        walking = true;
                        player.facing = Direction::Right;
                    }

                    // Speed up the player when dashing. On the ground they move automatically,
                    // while in the air they only move when explicitly pressed (unless air dashing).
                    if player.is_dashing() && (player.on_ground || player.is_air_dashing || walking)
                    {
                        speed_x = DASH_SPEED;
                        if matches!(player.facing, Direction::Left) {
                            speed_x *= -1;
                        }
                    }

                    // The ground is slippery in the Arctic stage.
                    if player.on_ground && matches!(ctx.map.map_type, MapType::Arctic) {
                        if player.slip_speed == 0 {
                            player.slip_speed = speed_x;
                        } else if player.slip_speed.signum() == speed_x.signum() {
                            player.slip_speed = player.slip_speed.abs().max(speed_x.abs())
                                * player.slip_speed.signum();
                            speed_x = player.slip_speed;
                        } else {
                            // Player is going against the slide - slowly decrease the slip speed.
                            let dec = (speed_x / SPEED_SCALE_FACTOR).abs();
                            player.slip_speed =
                                (player.slip_speed.abs() - dec).max(0) * player.slip_speed.signum();
                            speed_x = player.slip_speed;
                        }
                    } else {
                        player.slip_speed = 0;
                    }
                    move_x = Self::scale_speed(speed_x, frame);

                    if inventory.weapon_has_uses_left(player.weapon) {
                        if matches!(player.player_type, PlayerType::Shooter) {
                            let shoot_btn = input.is_pressed(Button::A);
                            let shoot_simple = input.just_pressed(Button::A);
                            let shoot_charged = !shoot_btn && player.charge_timer >= 30;
                            if (shoot_simple || shoot_charged) && player.shoot_cooldown == 0 {
                                inventory.decrease_weapon_uses(player.weapon);
                                player.shoot_cooldown = player.get_attack_cooldown();
                                trigger_attack = true;
                            }

                            if !shoot_btn && !trigger_attack {
                                player.charge_timer = 0;
                            } else if shoot_btn {
                                player.charge_timer = player.charge_timer.saturating_add(1);
                            }
                        } else if input.just_pressed(Button::A) {
                            inventory.decrease_weapon_uses(player.weapon);
                            player.status = Status::Attacking {
                                cooldown: player.get_attack_cooldown(),
                            };
                            player.enemies_hit = 0;
                            player.sprite.set_animation(player.get_attack_animation());
                            player.is_air_dashing = false;
                            player.dash_timer = 0;
                        }
                    }

                    if input.just_pressed(Button::B) && inventory.contains(ItemType::Key) {
                        // Unlock a nearby door.
                        let interaction_hitbox = player.hitbox().expand(5);
                        for door in doors.iter_mut() {
                            let is_keyhole = map
                                .doors
                                .iter()
                                .find(|d| d.2.id == door.id)
                                .map(|d| d.2.locked)
                                .unwrap_or(false);
                            if door.locked
                                && is_keyhole
                                && interaction_hitbox.collides(&door.hitbox())
                            {
                                door.unlock();
                                doors_unlocked.set(door.id);
                                doors_locked.clear(door.id);
                                inventory.remove(ItemType::Key);
                                break;
                            }
                        }
                    }
                }

                if !player.is_air_dashing {
                    player.h_speed += GRAVITY;
                    // Jump lower when the jump button is not pressed for the whole jump.
                    if !jump_pressed && player.h_speed < 0 {
                        player.h_speed += 2 * GRAVITY;
                    }
                } else {
                    player.h_speed = 0;
                }

                if player.is_sliding_down_wall() {
                    player.h_speed = SLIDE_SPEED;
                }
                if let Some(direction) = player.wall_jump_direction {
                    if player.h_speed < 0 {
                        // We're wall jumping - Cancel the jump if the player moves away on their own accord.
                        if direction != player.facing {
                            player.wall_jump_direction = None;
                        } else if player.should_push_away_from_wall() {
                            // Push the player away from the wall.
                            move_x = if matches!(direction, Direction::Left) {
                                1
                            } else {
                                -1
                            };
                        }
                    }
                }

                let move_y = Self::scale_speed(player.h_speed, frame);
                hits = Some(physics::try_move(
                    player,
                    map,
                    ctx.map.scroll_offset,
                    &ctx.map.doors,
                    move_x,
                    move_y,
                ));

                if player.h_speed >= 0 {
                    // Toggle wall slide state: Enable if the player is hugging the wall while falling.
                    if walking
                        && player.x == player.prev_x
                        && inventory.contains(ItemType::Walljump)
                    {
                        player.wall_jump_direction = Some(player.facing);
                        player.double_jump_available = true;
                        player.air_dash_available = true;
                    } else {
                        player.wall_jump_direction = None;
                    }
                }
                if player.y != player.prev_y {
                    player.on_ground = false;
                }

                let mut just_landed = false;
                // Tried to move up but didn't - bumped into the ceiling.
                if move_y < 0 && player.y - player.prev_y >= 0 {
                    player.h_speed = SPEED_SCALE_FACTOR;
                } else if move_y > 0 && player.y - player.prev_y <= 0 {
                    // Tried to move down but didn't - standing on a platform.
                    if !player.on_ground {
                        just_landed = true;
                        player.on_ground = true;
                        player.wall_jump_direction = None;
                        player.dash_timer = 0;
                        player.is_air_dashing = false;
                        player.double_jump_available = true;
                        player.air_dash_available = true;
                    }
                    player.h_speed = 0;
                }

                if move_x != 0 && player.x == player.prev_x {
                    // Hit wall - stop slipping.
                    player.slip_speed = 0;
                }

                if player.is_dashing() {
                    player.dash_timer -= 1;
                    if !player.on_ground && !player.is_air_dashing {
                        // Keep dashing in the air - only stop once the ground has been reached.
                        player.dash_timer = player.dash_timer.max(1);
                    } else if !keep_dashing || (player.is_air_dashing && player.dash_timer == 0) {
                        player.dash_timer = 0;
                        player.is_air_dashing = false;
                    }
                    if !prev_sliding_down_wall && player.is_sliding_down_wall() {
                        player.dash_timer = 0;
                        player.is_air_dashing = false;
                    }
                    if prev_facing != player.facing {
                        player.is_air_dashing = false;
                    }
                }

                player.sprite.maybe_set_animation(if !player.on_ground {
                    if player.is_air_dashing {
                        PlayerSprite::Anim::Dash
                    } else if player.h_speed < 0 {
                        if player.should_play_wall_jump_animation() {
                            PlayerSprite::Anim::WallJump
                        } else {
                            PlayerSprite::Anim::JumpUp
                        }
                    } else if player.is_sliding_down_wall() {
                        PlayerSprite::Anim::WallSlide
                    } else {
                        PlayerSprite::Anim::JumpDown
                    }
                } else if player.should_play_landing_animation(just_landed) {
                    PlayerSprite::Anim::Land
                } else if player.is_dashing() {
                    PlayerSprite::Anim::Dash
                } else if walking {
                    PlayerSprite::Anim::Walk
                } else if player.should_play_dash_stop_animation() {
                    PlayerSprite::Anim::DashStop
                } else if player.should_play_ground_attack_animation() {
                    PlayerSprite::Anim::Attack
                } else {
                    PlayerSprite::Anim::Idle
                } as usize);
                player.sprite.flip_h = matches!(player.facing, Direction::Left);

                if player.hitbox().y > 128 + SCREEN_HEIGHT as i16 {
                    // Fell down a bottomless pit
                    player.kill();
                }
            }
            Status::KnockedBack {
                direction,
                cooldown,
            } => {
                if cooldown > 20 {
                    let offs = direction.to_offset();
                    hits = Some(physics::try_move(
                        player,
                        map,
                        ctx.map.scroll_offset,
                        &ctx.map.doors,
                        offs.0,
                        offs.1,
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

                // Start weapon triggers (e.g. projectile shooting) on the frame the slash starts.
                if cooldown == player.get_attack_cooldown() - MELEE_TRIGGER_FRAME {
                    trigger_attack = true;
                }

                // Hit enemies
                if let Some(hurtbox) = player.get_hurtbox() {
                    for (i, enemy) in enemies.iter().enumerate() {
                        if is_bitmask_set(player.enemies_hit, enemy.id) {
                            // Hit enemies only once per attack.
                            continue;
                        }
                        if hurtbox.collides(&enemy.hitbox()) {
                            set_bitmask(&mut enemies_to_hit, i as u16);
                            set_bitmask(&mut player.enemies_hit, enemy.id);
                        }
                    }

                    // Hit switches
                    for s in 0..ctx.map.switches.len() {
                        let id = ctx.map.switches[s].id;
                        if ctx.map.switches_completed.is_set(id) || ctx.map.switches[s].pending {
                            continue;
                        }
                        if hurtbox.collides(&ctx.map.switches[s].hitbox()) {
                            ctx.map.switches[s].pending = true;
                        }
                    }
                }

                // The ground is slippery in the Arctic stage.
                if player.on_ground
                    && matches!(ctx.map.map_type, MapType::Arctic)
                    && player.slip_speed != 0
                {
                    let move_x = Self::scale_speed(player.slip_speed, frame);
                    Some(physics::try_move(
                        player,
                        map,
                        ctx.map.scroll_offset,
                        &ctx.map.doors,
                        move_x,
                        1,
                    ));
                    // Fell down a cliff - stop attacking.
                    if player.prev_y != player.y {
                        player.status = Status::Idle;
                    }
                }

                player
                    .sprite
                    .maybe_set_animation(player.get_attack_animation());
                player.sprite.flip_h = matches!(player.facing, Direction::Left);
            }
        }

        if player.double_tap_timer > 0 {
            player.double_tap_timer -= 1;
        }

        if player.shoot_cooldown > 0 {
            player.shoot_cooldown -= 1;
        }

        if player.is_active() {
            if let Some(hits) = &hits {
                if hits.touches_tile(MapTileAttribute::Spike) {
                    #[cfg(not(feature = "god_mode"))]
                    player.kill();
                }
            }
        }

        player.sprite.update();
        player.update_weapon_sprite();
        player.update_explosion_sprites();

        if trigger_attack {
            weapon.on_attack()(ctx);
            if ctx.player.weapon.can_charge() {
                ctx.player.charge_timer = 0;
            }
        }
        if enemies_to_hit != 0 {
            for i in 0..32 {
                if is_bitmask_set(enemies_to_hit, i as u16) {
                    weapon.on_melee_hit()(ctx, i);
                }
            }
        }
    }

    fn update_weapon_sprite(&mut self) {
        if !matches!(self.player_type, PlayerType::Melee) {
            return;
        }

        let center = self.hitbox().center();
        let flip_h = self.sprite.flip_h;
        let attacking = matches!(self.status, Status::Attacking { .. });
        if let Some(s) = &mut self.weapon_sprite {
            if !attacking {
                s.set_animation(PlayerSwordSprite::Anim::Off as usize);
                return;
            }
            s.maybe_set_animation(PlayerSwordSprite::Anim::Slash as usize);
            let (dx, dy) = self.weapon.melee_offset(s.next_frame(), flip_h);
            s.set_position(center.0 + dx, center.1 + dy);
            s.update();
            s.flip_h = flip_h;
        }
    }

    fn update_explosion_sprites(&mut self) {
        if !matches!(self.status, Status::Dying { .. }) {
            return;
        }

        for i in 0..self.explosion_sprites.len() {
            let mut remove = false;
            if let Some(s) = &mut self.explosion_sprites[i] {
                s.update();
                let oob_right = s.x > 128 + SCREEN_WIDTH as u16;
                let oob_left = s.x < 128;
                let oob_down = s.y > 128 + SCREEN_HEIGHT as u16;
                let oob_up = s.y < 128;
                let (dx, dy, oob) = match i {
                    0 => (1, 0, oob_right),
                    1 => (0, 1, oob_down),
                    2 => (-1, 0, oob_left),
                    3 => (0, -1, oob_up),
                    4 => (1, 1, oob_right && oob_down),
                    5 => (-1, 1, oob_left && oob_down),
                    6 => (1, -1, oob_right && oob_up),
                    _ => (-1, -1, oob_left && oob_up),
                };
                s.set_position(s.x as i16 + dx, s.y as i16 + dy);
                if oob {
                    remove = true;
                }
            }
            if remove {
                self.explosion_sprites[i] = None;
            }
        }
    }

    /// Whether the level reset button combo (A+B+C) has been pressed.
    pub fn reset_pressed(ctx: &mut Ctx) -> bool {
        if !ctx.player.is_active() {
            return false;
        }
        if let Some(input) = ctx.controller.controller_state(0) {
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
        false
    }

    /// Scales player speed
    /// Takes raw speed value and current frame
    /// Returns distance in pixels player should move this frame
    fn scale_speed(speed: i16, frame: u32) -> i16 {
        let abs_scaled_speed =
            i16::try_from(Self::scale_abs_speed(speed.unsigned_abs(), frame)).unwrap();
        if speed < 0 {
            -abs_scaled_speed
        } else {
            abs_scaled_speed
        }
    }

    fn scale_abs_speed(speed: u16, frame: u32) -> u16 {
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
            if (frame.wrapping_mul(fract_speed as u32) % (SPEED_SCALE_FACTOR as u32))
                < (fract_speed as u32)
            {
                return scaled_speed + 1;
            }
        }
        scaled_speed
    }

    /// Find the nearest ground by moving the player down until it hits a solid platform.
    pub fn move_to_ground(&mut self, map: &Map) {
        let mut prev_y = self.y;
        for _ in 0..100 {
            physics::try_move(self, &map.map_data, map.scroll_offset, &map.doors, 0, 1);
            if prev_y == self.y {
                break; // Found solid ground
            }
            prev_y = self.y;
        }
    }

    fn should_play_wall_jump_animation(&self) -> bool {
        self.sprite.current_animation() == PlayerSprite::Anim::WallSlide as usize
            || self.sprite.current_animation() == PlayerSprite::Anim::WallJump as usize
    }

    fn should_push_away_from_wall(&self) -> bool {
        self.sprite.current_animation() == PlayerSprite::Anim::WallJump as usize
            && !self.sprite.is_animation_finished()
    }

    fn should_play_landing_animation(&self, just_landed: bool) -> bool {
        if just_landed {
            return true;
        }
        // Stop playing once the animation has finished.
        self.sprite.current_animation() == PlayerSprite::Anim::Land as usize
            && !self.sprite.is_animation_finished()
    }

    fn should_play_ground_attack_animation(&self) -> bool {
        if !self.on_ground {
            return false;
        }
        if matches!(self.status, Status::Attacking { .. }) {
            return true;
        }
        // Stop playing once the animation has finished.
        self.sprite.current_animation() == PlayerSprite::Anim::Attack as usize
            && !self.sprite.is_animation_finished()
    }

    fn should_play_dash_stop_animation(&self) -> bool {
        if self.is_dashing() {
            return false;
        }
        self.sprite.current_animation() == PlayerSprite::Anim::Dash as usize
            || (self.sprite.current_animation() == PlayerSprite::Anim::DashStop as usize
                && !self.sprite.is_animation_finished())
    }

    fn get_attack_animation(&self) -> usize {
        if matches!(self.player_type, PlayerType::Shooter) {
            panic!("Shooter player attack animation is handled separately");
        }
        if self.on_ground {
            PlayerMeleeSprite::Anim::Attack as usize
        } else {
            PlayerMeleeSprite::Anim::ZjumpAttack as usize
        }
    }

    pub fn palette_type(&self) -> palettes::PaletteContext {
        match self.player_type {
            PlayerType::Shooter => palettes::PaletteContext::PlayerShooter,
            PlayerType::Melee => palettes::PaletteContext::PlayerMelee,
        }
    }

    fn get_hitbox(&self) -> Hitbox {
        match self.player_type {
            PlayerType::Shooter => Hitbox {
                x: self.x + 8,
                y: self.y + 8,
                w: 24,
                h: 32,
            },
            PlayerType::Melee => Hitbox {
                x: self.x + 8,
                y: self.y + 8,
                w: 24,
                h: 32,
            },
        }
    }

    fn get_attack_cooldown(&self) -> u8 {
        match self.player_type {
            PlayerType::Shooter => 10,
            PlayerType::Melee => 28,
        }
    }

    fn get_hurtbox(&self) -> Option<Hitbox> {
        if !matches!(self.player_type, PlayerType::Melee) {
            return None;
        }
        let hitbox = self.hitbox();

        if let Some(s) = &self.weapon_sprite {
            let hurtbox = self
                .weapon
                .melee_hurtbox(s.next_frame(), self.sprite.flip_h);
            if let Some(hurtbox) = hurtbox {
                let center = hitbox.center();
                return Some(hurtbox.offset(center.0, center.1));
            }
        }
        None
    }

    #[cfg(feature = "tests")]
    pub fn is_playing_dash_animation(&self) -> bool {
        self.sprite.current_animation() == crate::res::sprites::player::Anim::Dash as usize
    }

    #[cfg(feature = "tests")]
    pub fn is_air_dashing(&self) -> bool {
        self.is_air_dashing
    }

    #[cfg(feature = "tests")]
    pub fn dash_timer(&self) -> u16 {
        self.dash_timer
    }

    #[cfg(feature = "tests")]
    pub fn double_jump_available(&self) -> bool {
        self.double_jump_available
    }

    pub fn set_weapon(&mut self, weapon: WeaponType, res_state: &mut State, vdp: &mut TargetVdp) {
        self.weapon = weapon;
        self.palette = palettes::get_palette(Palette::A, self.palette_type());
        vdp.set_palette(Palette::A, &self.palette);
        if let (Some(sprite), Some(tiles_idx)) = (&mut self.weapon_sprite, weapon.tiles_idx()) {
            res_state.switch_sprite_tiles(sprite, tiles_idx);
        } else {
            self.weapon_sprite = weapon.get_sprite(res_state, vdp);
        }
    }
}

fn get_sprite(player_type: PlayerType, res_state: &mut State, vdp: &mut TargetVdp) -> BigSprite {
    let sprite = match player_type {
        PlayerType::Shooter => crate::res::sprites::player::new(
            res_state, vdp, /* singleton= */ true, /* keep_loaded= */ false,
        ),
        PlayerType::Melee => crate::res::sprites::player_melee::new(
            res_state, vdp, /* singleton= */ true, /* keep_loaded= */ false,
        ),
    };
    sprite
}

fn get_explosion_sprite(
    player_type: PlayerType,
    res_state: &mut State,
    vdp: &mut TargetVdp,
) -> BigSprite {
    let sprite = match player_type {
        PlayerType::Shooter => crate::res::sprites::player_explosion::new(
            res_state, vdp, /* singleton= */ false, /* keep_loaded= */ false,
        ),
        PlayerType::Melee => crate::res::sprites::player_melee_explosion::new(
            res_state, vdp, /* singleton= */ false, /* keep_loaded= */ false,
        ),
    };
    sprite
}

fn set_bitmask(bitmask: &mut u32, id: u16) {
    *bitmask += 1 << (id as u32);
}

fn is_bitmask_set(bitmask: u32, id: u16) -> bool {
    bitmask & (1 << (id as u32)) != 0
}

impl Entity for Player {
    fn hitbox(&self) -> Hitbox {
        self.get_hitbox()
    }

    fn render(
        &mut self,
        res_state: &mut State,
        vdp: &mut TargetVdp,
        renderer: &mut TargetRenderer,
    ) {
        if !self.is_active() {
            return;
        }
        if self.invulnerability_timer > 0 && (self.invulnerability_timer / 4) % 2 == 0 {
            return;
        }
        if matches!(self.player_type, PlayerType::Shooter) && self.shoot_cooldown > 0 {
            self.sprite.tileset_shift = 120; // 4 columns * 30 tiles/frame
        } else {
            self.sprite.tileset_shift = 0;
        }
        if matches!(self.status, Status::Dying { .. }) {
            for s in &mut self.explosion_sprites {
                if let Some(s) = s {
                    s.render(res_state, vdp, renderer);
                }
            }
        }
        self.sprite.render(res_state, vdp, renderer);
        if matches!(self.status, Status::Attacking { .. }) {
            if let Some(s) = &mut self.weapon_sprite {
                s.render(res_state, vdp, renderer);
            }
        }
    }

    fn set_position(&mut self, x: i16, y: i16) {
        self.x = x;
        self.y = y;
        if let Status::BeamingIn { sprite_y } = self.status {
            self.sprite.set_position(x, sprite_y);
        } else {
            self.sprite.set_position(x, y);
        }
    }

    fn move_relative(&mut self, dx: i16, dy: i16) {
        self.set_position(self.x + dx, self.y + dy);
    }
}
