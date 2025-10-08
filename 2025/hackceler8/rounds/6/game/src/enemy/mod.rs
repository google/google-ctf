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

pub mod boss;
mod harmless;
mod melee;
mod shooter;
mod singer;

use resources::MapTileAttribute;

use crate::big_sprite::BigSprite;
use crate::data;
use crate::entity::*;
use crate::game;
use crate::game::Ctx;
use crate::get_map_mut;
use crate::physics;
use crate::player;
use crate::res::enemies;
use crate::res::enemies::EnemyType;
use crate::res::sprites::crown as CrownSprite;
use crate::res::sprites::fall as FallSprite;
use crate::resource_state::State;
use crate::walk::WalkData;
use crate::walk::WalkState;
use crate::Direction;
use crate::Player;
use crate::Projectile;

/// Stop knockback after 30 frames (0.5s)
pub const KNOCKBACK_COOLDOWN: u8 = 30;
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
    sings: bool,
    tracks: bool,
    flies: bool,
    /// Hitbox relative to the sprite's x and y coordinates.
    hitbox: Hitbox,
}

/// Enemy properties parsed from the map that can override the
/// default properties.
pub struct EnemyProperties {
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

pub struct Enemy {
    pub x: i16,
    pub y: i16,
    pub id: u16,
    facing: Direction,
    sprite: BigSprite,
    /// Sprite of the crown worn by minibosses.
    /// Only set if this enemy is a minibooss
    crown_sprite: Option<BigSprite>,
    /// Sprite displayed when the enemy is falling down a hole.
    fall_sprite: BigSprite,
    pub status: Status,
    stats: Stats,
    pub invulnerable: bool,
    /// Flags the miniboss gives when defeated. Only applicable to minibosses.
    flags: u16,
    pub enemy_type: EnemyType,
    walk_state: WalkState,
    enemy_impl: EnemyImpl,
}

/// Collection of enemy type-specific functions.
pub struct EnemyImpl {
    stats: fn(EnemyType) -> Stats,
    update_animation: fn(enemy: &mut Enemy, walked: bool),
}

pub enum Status {
    KnockedBack { direction: (i16, i16), cooldown: u8 },
    Idle,
    Shooting { cooldown: u8 },
    Singing,
    Dying { cooldown: u16, falling: bool },
}

impl Enemy {
    pub fn new(
        enemy_type: EnemyType,
        map_x: i16,
        map_y: i16,
        id: u16,
        properties: &'static EnemyProperties,
        res_state: &mut State,
        vdp: &mut TargetVdp,
    ) -> Enemy {
        let enemy_impl = match enemy_type {
            EnemyType::Angel
            | EnemyType::AngelMinion
            | EnemyType::Blob
            | EnemyType::Goblin
            | EnemyType::Octopus
            | EnemyType::Orc
            | EnemyType::OrcMinion => melee::new(),
            EnemyType::Archer | EnemyType::Flameboi => shooter::new(),
            EnemyType::Siren => singer::new(),
            EnemyType::Rabbit => harmless::new(),
            EnemyType::Boss => boss::new(),
        };
        let stats = (enemy_impl.stats)(enemy_type).apply_properities(properties);
        let center = stats.hitbox.center();
        let sprite_x = map_x + 128 - center.0;
        let sprite_y = map_y + 128 - center.1;
        let mut sprite =
            enemies::sprite_init_fn(enemy_type)(res_state, vdp, /* keep_loaded= */ false);
        sprite.set_position(sprite_x, sprite_y);

        let mut enemy = Enemy {
            facing: Direction::Down,
            x: sprite_x,
            y: sprite_y,
            id,
            sprite,
            crown_sprite: None,
            fall_sprite: FallSprite::new(res_state, vdp, /* keep_loaded= */ false),
            status: Status::Idle,
            stats,
            invulnerable: properties.invulnerable,
            flags: properties.flags.unwrap_or(0),
            enemy_type,
            walk_state: WalkState::new(properties.walk_data),
            enemy_impl,
        };
        (enemy.enemy_impl.update_animation)(&mut enemy, /*walking*/ false);
        if enemy.is_miniboss() {
            let mut crown_sprite = CrownSprite::new(res_state, vdp, /* keep_loaded= */ false);
            crown_sprite.set_anim(CrownSprite::Anim::Idle as usize);
            enemy.crown_sprite = Some(crown_sprite);
        }
        enemy
    }

    pub fn update(ctx: &mut Ctx, enemy_id: usize) {
        let mut should_save = false;
        let closest_player_id = Self::get_closest_player(ctx, enemy_id);
        let enemy = &mut ctx.world.enemies[enemy_id];
        let map = get_map_mut!(ctx);
        let mut walking = false;
        let mut hits = None;

        match enemy.status {
            Status::Dying {
                falling,
                mut cooldown,
            } => {
                cooldown = cooldown + 1;
                if cooldown >= enemy.death_cooldown() {
                    // Add flags for newly defeated bosses.
                    if (enemy.is_miniboss() || enemy.is_boss())
                        && ctx.defeated_minibosses & enemy.enemy_type as u16 == 0
                    {
                        ctx.defeated_minibosses |= enemy.enemy_type as u16;
                        ctx.captured_flags += enemy.flags;
                        should_save = true;
                    }
                }

                enemy.status = Status::Dying { cooldown, falling };
            }
            Status::Idle => {
                for p in 0..ctx.players.len() {
                    if closest_player_id != p {
                        continue;
                    }
                    let player = &mut ctx.players[p];
                    let player_center = player.hitbox().center();
                    let enemy_center = enemy.hitbox().center();
                    let (mut dx, mut dy) = if enemy.stats.tracks && enemy.walk_state.data.is_empty()
                    {
                        // Follow the player.
                        (
                            player_center.0 - enemy_center.0,
                            player_center.1 - enemy_center.1,
                        )
                    } else {
                        // Follow predefined walk data.
                        enemy.walk_state.update()
                    };

                    if dx != 0 || dy != 0 {
                        walking = true;
                        enemy.face_dir(dx, dy);
                    } else if enemy.walk_state.data.is_empty() {
                        enemy.face_player(player);
                    }

                    let mut speed_per_frame = enemy.stats.speed / 64;
                    if speed_per_frame == 0 {
                        // Less than 1px per frame
                        // So instead we move 1px every N frames
                        let frame_per_pixel = 64 / enemy.stats.speed as u16;
                        if ctx.frame % frame_per_pixel == 0 {
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
                    if dx != 0 || dy != 0 {
                        hits = Some(physics::try_move(enemy, map, &ctx.world.doors, dx, dy));
                    }

                    if enemy.stats.melee && enemy.hitbox().collides(&player.hitbox()) {
                        let push_dir = match enemy.facing {
                            Direction::Left => (-60i16, 0i16),
                            Direction::Right => (60i16, 0i16),
                            Direction::Up => (0i16, -60i16),
                            Direction::Down => (0i16, 60i16),
                        };
                        player.on_hit(push_dir, enemy.stats.strength);
                    }

                    if enemy.stats.shoots && ctx.frame % shooter::SHOOT_FREQUENCY == 0 {
                        enemy.face_player(player);
                        enemy.status = Status::Shooting {
                            cooldown: shooter::SHOOT_COOLDOWN,
                        };
                    }

                    if enemy.stats.sings
                        && singer::within_singing_distance(&enemy.hitbox(), &player.hitbox())
                    {
                        enemy.status = Status::Singing;
                    }
                }
            }
            Status::Shooting { cooldown } => {
                if cooldown == shooter::SHOOT_COOLDOWN - shooter::PROJECTILE_DELAY
                    && ctx.players.len() > closest_player_id
                {
                    let player = &mut ctx.players[closest_player_id];
                    let (offs_x, offs_y) =
                        shooter::get_projectile_start_offset(enemy.enemy_type, enemy.facing);
                    let projectile = Projectile::new(
                        enemy.id,
                        enemy.x + offs_x,
                        enemy.y + offs_y,
                        player.x - enemy.x,
                        player.y - enemy.y,
                        enemy.stats.strength,
                        shooter::get_projectile_sprite(
                            enemy.enemy_type,
                            &mut ctx.res_state,
                            &mut ctx.vdp,
                        ),
                    );
                    if ctx.world.projectiles.push(projectile).is_err() {
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
            Status::Singing => {
                // Lure in players.
                let mut lured_one = false;
                for p in 0..ctx.players.len() {
                    let player = &mut ctx.players[p];
                    if !player.is_active() {
                        continue;
                    }
                    if closest_player_id == p {
                        enemy.face_player(player);
                    }
                    if !singer::within_singing_distance(&enemy.hitbox(), &player.hitbox()) {
                        continue;
                    }
                    lured_one = true;
                    let dx = (enemy.x - player.x).signum();
                    let dy = (enemy.y - player.y).signum();
                    if !matches!(player.status, player::Status::KnockedBack { .. }) {
                        if ctx.frame % singer::LURE_EVERY_NTH_FRAME == 0 {
                            physics::try_move(player, map, &ctx.world.doors, dx, dy);
                        }
                    }
                    if enemy.stats.melee && enemy.hitbox().collides(&player.hitbox()) {
                        player.on_hit((-dx * 60, -dy * 60), enemy.stats.strength);
                    }
                }
                if !lured_one {
                    enemy.status = Status::Idle;
                }
            }
            Status::KnockedBack {
                direction,
                cooldown,
            } => {
                enemy.facing = if direction.0.abs() > direction.1.abs() {
                    if direction.0 < 0 {
                        Direction::Left
                    } else {
                        Direction::Right
                    }
                } else if direction.1 > 0 {
                    Direction::Down
                } else {
                    Direction::Up
                };
                if cooldown > 20 && enemy.can_be_pushed_back() {
                    hits = Some(physics::try_move(
                        enemy,
                        map,
                        &ctx.world.doors,
                        direction.0 / 60,
                        direction.1 / 60,
                    ));
                }
                if cooldown > 20 && enemy.is_boss() {
                    ctx.tint_rgb = (8, 8, 8);
                }
                enemy.status = if cooldown > 0 {
                    Status::KnockedBack {
                        direction,
                        cooldown: cooldown - 1,
                    }
                } else {
                    Status::Idle
                };
            }
        }

        if enemy.is_alive() && !enemy.stats.flies {
            if let Some(hits) = hits {
                if hits.touches_tile(MapTileAttribute::Spike) {
                    enemy.kill(/*falling=*/ false);
                }
                if hits.immersed_in_tile(MapTileAttribute::Hole) {
                    enemy.kill(/*falling=*/ true);
                }
            }
        }

        enemy.update_animation(walking);
        enemy.update_sub_sprite_position();

        if should_save {
            ctx.save_game_challenges();
        }
    }

    pub fn kill(&mut self, falling: bool) {
        if !matches!(self.status, Status::Dying { .. }) {
            self.status = Status::Dying {
                cooldown: 0,
                falling,
            };
            if falling {
                self.fall_sprite.set_anim(FallSprite::Anim::Fall as usize);
            }
        }
    }

    pub fn on_hit(&mut self, direction: (i16, i16), damage: u16) {
        if !self.is_alive() || self.invulnerable {
            return;
        }
        if self.stats.health != 0 && self.stats.health <= damage {
            self.stats.health = 0;
            self.status = Status::Dying {
                cooldown: 0,
                falling: false,
            };
            return;
        }
        self.stats.health -= damage;
        self.status = Status::KnockedBack {
            direction,
            cooldown: KNOCKBACK_COOLDOWN,
        };
    }

    pub fn is_alive(&self) -> bool {
        !matches!(self.status, Status::Dying { .. })
    }

    /// Returns true if the enemy should be unloaded from memory.
    /// This mean the entity is fully dead and not rendered anymore.
    pub fn should_unload(&self) -> bool {
        match self.status {
            Status::Dying {
                falling: _,
                cooldown,
            } => cooldown == self.death_cooldown(),
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

    fn can_be_pushed_back(&self) -> bool {
        !self.is_boss()
    }

    fn is_falling(&self) -> bool {
        matches!(
            self.status,
            Status::Dying {
                cooldown: _,
                falling: true,
            }
        )
    }

    fn face_player(&mut self, player: &Player) {
        self.face_dir(player.x - self.x, player.y - self.y);
    }

    fn face_dir(&mut self, dx: i16, dy: i16) {
        self.facing = if dx.abs() > dy.abs() {
            if dx < 0 {
                Direction::Left
            } else {
                Direction::Right
            }
        } else if dy > 0 {
            Direction::Down
        } else {
            Direction::Up
        };
    }

    fn update_animation(&mut self, walking: bool) {
        (self.enemy_impl.update_animation)(self, walking);

        if self.is_falling() {
            self.fall_sprite.update()
        }

        if let Some(crown_sprite) = &mut self.crown_sprite {
            match self.status {
                Status::Dying { .. } => {
                    crown_sprite.maybe_set_anim(CrownSprite::Anim::Die as usize);
                }
                Status::KnockedBack {
                    direction: _,
                    cooldown,
                } => {
                    // Just started
                    if cooldown == KNOCKBACK_COOLDOWN - 1 {
                        crown_sprite.set_anim(CrownSprite::Anim::Damage as usize);
                    }
                }
                _ => {
                    crown_sprite.maybe_set_anim(CrownSprite::Anim::Idle as usize);
                }
            }
            crown_sprite.update();
        }
    }

    fn update_sub_sprite_position(&mut self) {
        let center = self.hitbox().center();
        if let Some(crown_sprite) = &mut self.crown_sprite {
            let (mut dx, dy) = data::crown_offset(self.enemy_type, self.facing);
            dx -= 8;
            crown_sprite.set_position(center.0 + dx, center.1 + dy);
        }
        if self.is_falling() {
            self.fall_sprite.set_position(center.0 - 4, center.1 - 4);
        }
    }

    pub fn health(&self) -> u16 {
        self.stats.health
    }

    /// Returns an the ID of the player closest to this enemy.
    fn get_closest_player(ctx: &Ctx, enemy_id: usize) -> usize {
        let mut min_d = u32::MAX;
        let mut closest = game::MAX_PLAYERS;
        let center = &ctx.world.enemies[enemy_id].hitbox().center();
        for p in 0..ctx.players.len() {
            let player = &ctx.players[p];
            if !player.is_active() {
                continue;
            }
            let player_center = player.hitbox().center();
            let dx = (center.0 - player_center.0) as i32;
            let dy = (center.1 - player_center.1) as i32;
            let d = (dx * dx) as u32 + (dy * dy) as u32;
            if d < min_d {
                min_d = d;
                closest = p;
            }
        }
        closest
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

    fn render(&mut self, renderer: &mut TargetRenderer) {
        if let Some(crown_sprite) = &mut self.crown_sprite {
            crown_sprite.render(renderer);
        }
        if self.is_falling() {
            self.fall_sprite.render(renderer);
        } else if !self.is_boss() || boss::should_render_sprite(self) {
            self.sprite.render(renderer);
        }
    }

    #[expect(clippy::cast_sign_loss)]
    /// Set the absolute position of a sprite on the screen.
    fn set_position(&mut self, x: i16, y: i16) {
        self.x = x;
        self.y = y;
        self.sprite.set_position(x, y);
        self.update_sub_sprite_position();
    }

    fn move_relative(&mut self, dx: i16, dy: i16) {
        self.set_position(self.x + dx, self.y + dy);
    }
}
