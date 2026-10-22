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

use crate::big_sprite::BigSprite;
use crate::data;
use crate::entity::Hitbox;
use crate::game::Ctx;
use crate::projectile::Projectile;
use crate::res::sprites::charged_shot;
use crate::res::sprites::fireball;
use crate::res::sprites::player as PlayerSprite;
use crate::res::sprites::simple_shot;
use crate::resource_state::State;
use crate::PlayerType;
use megahx8::*;

/// Weapons that are unlocked by default on starting a level.
pub const DEFAULT_WEAPONS: &[WeaponType] = &[
    WeaponType::Gun,
    WeaponType::Sword,
    WeaponType::ThreeGun,
    WeaponType::StrongGun,
    WeaponType::FlameSword,
    WeaponType::DoubleEdgedSword,
    WeaponType::StrongSword,
];

#[derive(PartialEq, Copy, Clone)]
pub enum WeaponType {
    // Basic gun and sword
    Gun,
    Sword,
    // Shoots 3 projectiles
    ThreeGun,
    // Gun that deals double damage but can only be used a limited amount of times.
    StrongGun,
    // Shoots a fireball on slashes
    FlameSword,
    // Sword that deals more damage but also damages the player
    DoubleEdgedSword,
    // Sword that deals double damage but can only be used a limited amount of times.
    StrongSword,
}

impl WeaponType {
    /// The string that should be displayed in the inventory.
    pub fn display_name(&self) -> &str {
        match self {
            WeaponType::Gun => "Gun",
            WeaponType::Sword => "Sword",
            WeaponType::ThreeGun => "3-Gun",
            WeaponType::StrongGun => "StrngGun",
            WeaponType::FlameSword => "FlameSword",
            WeaponType::DoubleEdgedSword => "2-Edge Sword",
            WeaponType::StrongSword => "StrngSword",
        }
    }

    /// The player character type that can wield this weapon.
    pub fn player_type(&self) -> PlayerType {
        match self {
            WeaponType::Gun | WeaponType::ThreeGun | WeaponType::StrongGun => PlayerType::Shooter,
            WeaponType::Sword
            | WeaponType::FlameSword
            | WeaponType::DoubleEdgedSword
            | WeaponType::StrongSword => PlayerType::Melee,
        }
    }

    /// Whether this weapon supports charged attacks.
    pub fn can_charge(&self) -> bool {
        *self == WeaponType::Gun
    }

    pub fn tiles_idx(&self) -> Option<usize> {
        match self {
            WeaponType::Sword => Some(crate::res::sprites::player_sword::TILES_IDX),
            WeaponType::FlameSword => Some(crate::res::sprites::player_flamesword::TILES_IDX),
            WeaponType::DoubleEdgedSword => {
                Some(crate::res::sprites::player_doublesword::TILES_IDX)
            }
            WeaponType::StrongSword => Some(crate::res::sprites::player_strongsword::TILES_IDX),
            _ => None,
        }
    }

    pub fn get_sprite(&self, res_state: &mut State, vdp: &mut TargetVdp) -> Option<BigSprite> {
        match self {
            WeaponType::FlameSword => Some(crate::res::sprites::player_flamesword::new(
                res_state, vdp, /* singleton= */ true, /* keep_loaded= */ false,
            )),
            WeaponType::DoubleEdgedSword => Some(crate::res::sprites::player_doublesword::new(
                res_state, vdp, /* singleton= */ true, /* keep_loaded= */ false,
            )),
            WeaponType::StrongSword => Some(crate::res::sprites::player_strongsword::new(
                res_state, vdp, /* singleton= */ true, /* keep_loaded= */ false,
            )),
            WeaponType::Sword => Some(crate::res::sprites::player_sword::new(
                res_state, vdp, /* singleton= */ true, /* keep_loaded= */ false,
            )),
            _ => None,
        }
    }

    /// The maximum times the weapon can be used. None if there's no limit.
    pub fn max_uses(&self) -> Option<i16> {
        match self {
            WeaponType::StrongSword => Some(3),
            WeaponType::StrongGun => Some(3),
            _ => None,
        }
    }

    /// Function to call when the player starts attacking with the weapon.
    pub fn on_attack(&self) -> fn(ctx: &mut Ctx) {
        match self {
            WeaponType::Gun => gun_shoot,
            WeaponType::FlameSword => flame_shoot,
            WeaponType::StrongGun => strong_shoot,
            WeaponType::ThreeGun => triple_shoot,
            _ => nop,
        }
    }

    /// Function to call when an enemy gets hit with the melee weapon.
    pub fn on_melee_hit(&self) -> fn(ctx: &mut Ctx, enemy_id: usize) {
        match self {
            WeaponType::DoubleEdgedSword => double_sword_hit,
            WeaponType::StrongSword => strong_melee_hit,
            _ => basic_melee_hit,
        }
    }

    /// Returns the offset of the player's melee weapon for a given frame.
    pub fn melee_offset(&self, frame: usize, flip_h: bool) -> (i16, i16) {
        const PLAYER_SPRITE_WIDTH: i16 = 40;
        let (mut dx, dy) = if *self == WeaponType::StrongSword {
            match frame {
                0 => (-38, -74),
                2 => (-51, -31),
                3 => (-11, -70),
                4 => (19, -61),
                5 | 6 | 7 => (19, -58),
                _ => (0, 0),
            }
        } else {
            match frame {
                0 | 1 => (-32, -51),
                2 => (-40, -36),
                3 => (-3, -51),
                4 => (20, -38),
                5 | 6 | 7 => (18, -36),
                _ => (0, 0),
            }
        };

        if flip_h {
            dx = -PLAYER_SPRITE_WIDTH - dx;
            if *self == WeaponType::StrongSword {
                // Adjust for the wider sprite size of StrongSword (60 active pixels vs 40)
                dx -= 20;
            } else {
                // Adjust for the 64-wide sprite with 40 active pixels (64 - 40 = 24)
                dx -= 24;
            }
        }
        (dx, dy)
    }

    /// Returns the area of the melee weapon that should hurt enemies that touch it,
    /// depending on the weapon frame.
    pub fn melee_hurtbox(&self, frame: usize, flip_h: bool) -> Option<Hitbox> {
        if frame < 3 || frame > 7 {
            return None;
        }
        let mut hurtbox = if *self == WeaponType::StrongSword {
            match frame {
                3 => Hitbox {
                    x: -8,
                    y: -76,
                    w: 69,
                    h: 60,
                },
                4 => Hitbox {
                    x: 23,
                    y: -60,
                    w: 54,
                    h: 72,
                },
                _ => Hitbox {
                    x: 24,
                    y: 4,
                    w: 54,
                    h: 11,
                },
            }
        } else {
            match frame {
                3 => Hitbox {
                    x: -4,
                    y: -52,
                    w: 46,
                    h: 40,
                },
                4 => Hitbox {
                    x: 23,
                    y: -36,
                    w: 36,
                    h: 48,
                },
                _ => Hitbox {
                    x: 23,
                    y: 5,
                    w: 36,
                    h: 7,
                },
            }
        };

        if flip_h {
            hurtbox.x = -hurtbox.x - hurtbox.w as i16;
        }

        Some(hurtbox)
    }
}

fn nop(_: &mut Ctx) {}

fn spawn_projectile(
    ctx: &mut Ctx,
    rel_dx: i16,
    dy: i16,
    speed: i16,
    damage: u16,
    sprite: BigSprite,
) {
    let player = &ctx.player;
    let is_wall_anim = player.sprite.current_animation() == PlayerSprite::Anim::WallSlide as usize;
    let visual_flip_h = player.sprite.flip_h ^ is_wall_anim;
    let dx = if visual_flip_h { -rel_dx } else { rel_dx };
    let (offset_x, offset_y) = data::projectile_weapon_offset(visual_flip_h);
    let projectile = Projectile::new(
        player.x + offset_x,
        player.y + offset_y,
        dx,
        dy,
        speed,
        damage,
        sprite,
        /*is_player=*/ true,
    );
    if ctx.map.projectiles.push(projectile).is_err() {
        warn!("Failed to load projectile, vector full?");
    }
}

fn has_charged_bullet(ctx: &Ctx) -> bool {
    ctx.map
        .projectiles
        .iter()
        .any(|p| p.sprite.tiles_idx == charged_shot::TILES_IDX && !p.should_unload())
}

fn shoot_charged(ctx: &mut Ctx, damage: u16) {
    if has_charged_bullet(ctx) {
        // the charged_shot sprite is singleton, we cannot have more than one on the screen
        return;
    }
    let sprite = charged_shot::new(
        &mut ctx.res_state,
        &mut ctx.vdp,
        /* singleton= */ true,
        false,
    );
    spawn_projectile(
        ctx, /* rel_dx= */ 10, /* dy= */ 0, /* speed= */ 10, damage, sprite,
    );
}

fn gun_shoot(ctx: &mut Ctx) {
    let charge = ctx.player.charge_timer;
    let damage = match charge {
        75.. => 3,
        30.. => 2,
        _ => 1,
    };
    if damage > 1 {
        shoot_charged(ctx, damage);
    } else {
        let sprite = simple_shot::new(&mut ctx.res_state, &mut ctx.vdp, false, false);
        spawn_projectile(
            ctx, /*rel_dx=*/ 10, /*dy=*/ 0, /*speed=*/ 10, damage, sprite,
        );
    }
}

fn strong_shoot(ctx: &mut Ctx) {
    shoot_charged(ctx, /* damage= */ 2);
}

fn flame_shoot(ctx: &mut Ctx) {
    let sprite = fireball::new(&mut ctx.res_state, &mut ctx.vdp, false, false);
    spawn_projectile(
        ctx, /*rel_dx=*/ 10, /*dy=*/ 0, /*speed=*/ 10, /*damage=*/ 1, sprite,
    );
}

fn triple_shoot(ctx: &mut Ctx) {
    for i in -1..=1 {
        let sprite = simple_shot::new(&mut ctx.res_state, &mut ctx.vdp, false, false);
        spawn_projectile(
            ctx,
            /*rel_dx=*/ 10,
            /*dy=*/ i * 10,
            /*speed=*/ 4,
            /*damage=*/ 1,
            sprite,
        );
    }
}

fn basic_melee_hit(ctx: &mut Ctx, enemy_id: usize) {
    let enemy = &mut ctx.map.enemies[enemy_id];
    enemy.on_hit(/*damage=*/ 2);
}

fn strong_melee_hit(ctx: &mut Ctx, enemy_id: usize) {
    let enemy = &mut ctx.map.enemies[enemy_id];
    enemy.on_hit(/*damage=*/ 3);
}

fn double_sword_hit(ctx: &mut Ctx, enemy_id: usize) {
    let enemy = &mut ctx.map.enemies[enemy_id];
    enemy.on_hit(/*damage=*/ 3);
    ctx.player.on_hit(enemy.facing, /*damage=*/ 3);
}
