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
use crate::projectile;
use crate::res::items::ItemType;
use crate::res::sprites::player_base as PlayerSprite;
use crate::resource_state::State;
use crate::Direction;
use crate::PlaneAddress;
use crate::Projectile;

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
    pub shoots: bool,
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
            shoots: false,
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
        self.shoots = false;
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

        let mut remove_staff = false;

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

        let mut should_paint = false;
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
                        player.status = Status::Attacking {
                            cooldown: if player.shoots { 50 } else { 20 },
                        };
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
                        if player.shoots {
                            let center = attack_hitbox.center();
                            let fireball = Projectile::new(
                                projectile::PLAYER_SHOOTER_ID,
                                center.0 - 5,
                                center.1 - 10,
                                dx * 100,
                                dy * 100,
                                /*damage=*/ 1,
                                crate::res::sprites::fireball::new(
                                    &mut ctx.res_state,
                                    &mut ctx.vdp,
                                    /* keep_loaded= */ false,
                                ),
                            );
                            if ctx.world.projectiles.push(fireball).is_err() {
                                warn!("Failed to load projectile, vector full?");
                            }
                        } else {
                            for enemy in enemies {
                                if attack_hitbox.collides(&enemy.hitbox()) {
                                    enemy.on_hit((dx * 60, dy * 60), player.strength);
                                }
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
                    if input.just_pressed(Button::B)
                        && inventory.contains_equipped(ItemType::Pencil, player_id)
                    {
                        should_paint = true;
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
                    // The staff is one-time use only.
                    remove_staff = true;
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

        let center = player.hitbox().center();
        if should_paint {
            Self::paint(ctx, center);
        }

        if remove_staff {
            ctx.world.inventory.remove_staff(&mut ctx.players);
        }

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

    /// Use the last 8 empty slots of the boss tile map's palette for the paint colors.
    const PAINT_PALETTE: Palette = Palette::C;
    const PAINT_PALETTE_START: u16 = 8;
    /// Use the unused tiles towards the end of the boss map tileset for the paint tiles.
    const PAINT_TILE_START: u16 = 208;
    /// The magic picture that players have to draw to get a reward.
    const MAGIC_PICTURE_W: usize = 11;
    const MAGIC_PICTURE: [u16; 11 * 10] = [
        0xfff, 0x800, 0xfff, 0xfff, 0xfff, 0xfff, 0xfff, 0xfff, 0xfff, 0x800, 0xfff, 0x800, 0x088,
        0x800, 0xfff, 0xfff, 0xfff, 0xfff, 0xfff, 0x800, 0x088, 0x800, 0x800, 0xf0f, 0x088, 0x800,
        0x800, 0x800, 0x800, 0x800, 0x088, 0xf0f, 0x800, 0x800, 0x088, 0x800, 0x00f, 0x00f, 0x00f,
        0x00f, 0x00f, 0x800, 0x088, 0x800, 0x800, 0x00f, 0x00f, 0x088, 0x088, 0x088, 0x088, 0x088,
        0x00f, 0x00f, 0x800, 0x800, 0x088, 0x088, 0x088, 0x088, 0x088, 0x088, 0x088, 0x088, 0x088,
        0x800, 0x800, 0x088, 0xfff, 0xff0, 0x088, 0x088, 0x088, 0xff0, 0xfff, 0x088, 0x800, 0x800,
        0x088, 0xff0, 0x800, 0x088, 0x088, 0x088, 0x800, 0xff0, 0x088, 0x800, 0xfff, 0x800, 0x800,
        0x088, 0x088, 0x00f, 0x088, 0x088, 0x800, 0x800, 0xfff, 0xfff, 0xfff, 0xfff, 0x800, 0x800,
        0x800, 0x800, 0x800, 0xfff, 0xfff, 0xfff,
    ];
    /// The tile idx at position 0,0 of the boss map, relative to the boss map tileset.
    const TILE_00_RELATIVE_ID: u16 = 15;

    /// Paint the map tile at the given coordinates.
    fn paint(ctx: &mut Ctx, coords: (i16, i16)) {
        let plane_x = (coords.0 - 128) / 8;
        let plane_y = (coords.1 - 128) / 8;
        if plane_x < 0 || plane_x >= 40 || plane_y < 0 || plane_y >= 28 {
            // Out of the map bounds.
            return;
        }
        let tile_addr = PlaneAddress(plane_x as u16, plane_y as u16).to_address();

        let mut map_tiles = [TileFlags::new(); 64 * 28];
        ctx.vdp.get_plane_tiles(Plane::A, &mut map_tiles);
        let base_idx = map_tiles[0].tile_index() - Self::TILE_00_RELATIVE_ID;
        let tile_idx = map_tiles[tile_addr as usize].tile_index();

        // If there's already a paint tile in this position, increment its color.
        let current_paint_palette = Self::get_paint_palette(tile_idx, base_idx);
        let new_paint_color = if let Some(current_paint_palette) = current_paint_palette {
            Self::next_color(
                ctx.vdp
                    .get_color(Self::PAINT_PALETTE, current_paint_palette),
            )
        } else {
            0x00f
        };

        // Find the existing palette of the color or add a new one.
        let mut palette_pos = Self::PAINT_PALETTE_START;
        while ctx.vdp.get_color(Self::PAINT_PALETTE, palette_pos) != new_paint_color
            && Self::palette_in_use(&map_tiles, base_idx, palette_pos)
        {
            palette_pos += 1;
        }

        // Apply coloring - modify palette, tile, and map data.
        let paint_tile_idx =
            palette_pos - Self::PAINT_PALETTE_START + base_idx + Self::PAINT_TILE_START;
        ctx.vdp
            .set_color(Self::PAINT_PALETTE, palette_pos, new_paint_color);
        ctx.vdp
            .set_tiles(paint_tile_idx, &[Tile([palette_pos as u8 * 0x11; 32])]);
        let new_tile = TileFlags::for_tile(paint_tile_idx, Self::PAINT_PALETTE);
        ctx.vdp.set_plane_tiles(Plane::A, tile_addr, &[new_tile]);
        map_tiles[tile_addr as usize] = new_tile;

        // Damage the boss if the magic picture has been drawn.
        if let Some(boss_state) = &mut ctx.world.boss_state {
            if !boss_state.drew_magic_picture
                && Self::drew_magic_picture(&mut ctx.vdp, &map_tiles, base_idx)
            {
                boss_state.drew_magic_picture = true;
                let boss = ctx.world.enemies.iter_mut().find(|e| e.is_boss());
                if let Some(boss) = boss {
                    boss.on_hit((0, 0), 10);
                }
            }
        }
    }

    /// Gets the palette of the paint tile of the given index.
    /// Return None if this it not a paint tile.
    fn get_paint_palette(tile_idx: u16, base_idx: u16) -> Option<u16> {
        if tile_idx < base_idx + Self::PAINT_TILE_START {
            // Not a paint tile.
            return None;
        }
        Some(tile_idx - base_idx - Self::PAINT_TILE_START + Self::PAINT_PALETTE_START)
    }

    /// Gets the next rgb444 color to switch the specified color to.
    /// This cycles through 0x00F, 0x0F0, 0x0FF, 0xF00, etc.
    fn next_color(color: u16) -> u16 {
        let colors = [
            0x00f, 0x0f0, 0x0ff, 0xf00, 0xf0f, 0xff0, 0xfff, 0x008, 0x080, 0x088, 0x800, 0x808,
            0x880, 0x888,
        ];
        let pos = colors
            .iter()
            .position(|&x| x == color)
            .unwrap_or_else(|| panic!("Couldn't find color {:x}", color));
        return colors[(pos + 1) % colors.len()];
    }

    /// Checks if a given paint palette is currently in use on the map.
    fn palette_in_use(map_tiles: &[TileFlags], base_idx: u16, palette_pos: u16) -> bool {
        for tile in map_tiles {
            if Self::get_paint_palette(tile.tile_index(), base_idx) == Some(palette_pos) {
                return true;
            }
        }
        false
    }

    /// Checks if the player managed to draw the magic picture somewhere on the map.
    fn drew_magic_picture(vdp: &mut TargetVdp, map_tiles: &[TileFlags], base_idx: u16) -> bool {
        let map_x_len = 64;
        let map_y_len = map_tiles.len() / 64;
        for map_y in 0..map_y_len {
            for map_x in 0..map_x_len {
                let tile = map_tiles[map_x + map_y * map_x_len];
                if Self::get_paint_palette(tile.tile_index(), base_idx).is_none() {
                    continue;
                }

                let pic_x_len = Self::MAGIC_PICTURE_W;
                let pic_y_len = Self::MAGIC_PICTURE.len() / Self::MAGIC_PICTURE_W;

                if map_x + pic_x_len > map_x_len || map_y + pic_y_len > map_y_len {
                    continue;
                }

                'pic_search: for pic_y in 0..pic_y_len {
                    for pic_x in 0..pic_x_len {
                        let tile = map_tiles[map_x + pic_x + (map_y + pic_y) * map_x_len];
                        if let Some(palette) = Self::get_paint_palette(tile.tile_index(), base_idx)
                        {
                            if vdp.get_color(Self::PAINT_PALETTE, palette)
                                != Self::MAGIC_PICTURE[pic_x + pic_y * pic_x_len]
                            {
                                break 'pic_search;
                            }
                        } else {
                            break 'pic_search;
                        }
                        if pic_x + 1 == pic_x_len && pic_y + 1 == pic_y_len {
                            return true;
                        }
                    }
                }
            }
        }
        false
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
