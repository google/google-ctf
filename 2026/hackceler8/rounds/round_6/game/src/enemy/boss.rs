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
use crate::map_data;
use crate::res::enemies::EnemyType;
use crate::res::sprites::boss::Anim;
use crate::res::sprites::explosion as ExplosionSprite;
use crate::resource_state::State;
use crate::Player;
use core::mem::transmute;
use core::ptr::read_volatile;
use core::ptr::write_volatile;

pub(crate) fn new() -> EnemyImpl {
    EnemyImpl {
        stats,
        update_animation,
    }
}

fn stats(_enemy_type: EnemyType) -> Stats {
    Stats {
        speed: 16,
        health: 20,
        strength: 3,
        melee: true,
        shoots: false,
        hitbox: Hitbox {
            x: 6,
            y: 27,
            w: 51,
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

/// Boss related enemy state data.
pub struct BossState {
    /// Explosions for the boss death sequence.
    explosion_sprites: [BigSprite; 2],
    copy_player_inited: bool,
    pub copy_player: Player,
    // Bitfield for whether a given tile on the boss stage is painted.
    pub painted_tiles: [u8; map_data::WIDTH * map_data::HEIGHT / 8],
    pub current_player: *mut Player,
    pub next_player: *mut Player,
}

impl BossState {
    pub fn new(player: &mut Player, res_state: &mut State, vdp: &mut TargetVdp) -> BossState {
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
            copy_player_inited: false,
            copy_player: Player::new(player.player_type, res_state, vdp),
            painted_tiles: [0; map_data::WIDTH * map_data::HEIGHT / 8],
            current_player: player as *mut Player,
            next_player: player as *mut Player,
        }
    }

    pub fn paint_tile(ctx: &mut Ctx, x: i16, y: i16) {
        if ctx.map.boss_state.is_none() {
            return;
        }
        let state = ctx.map.boss_state.as_mut().unwrap();

        // Convert to map tile position.
        let x = (x as usize - 128) / 8;
        let y = (y as usize - 128) / 8;
        info!("Painting {},{}", x, y);

        // Direct access for faster execution.
        // SAFETY: The size of the array is exactly the same as that of the map.
        unsafe {
            let mut ptr: *mut u8 = transmute(&state.painted_tiles);
            ptr = ptr.offset((y * map_data::WIDTH + x) as isize / 8);
            let val = read_volatile(ptr);
            write_volatile(ptr, val ^ (1 << (x % 8)));
        }

        // Update graphics with the painted tile.
        ctx.map.redraw(&mut ctx.vdp, &mut ctx.res_state);
    }

    pub fn is_paint_at(&self, x: usize, y: usize) -> bool {
        return self.painted_tiles[(y * map_data::WIDTH + x) / 8] & (1 << (x % 8)) > 0;
    }

    pub fn update(ctx: &mut Ctx) {
        if ctx.map.boss_state.is_none() {
            return;
        }
        let state = ctx.map.boss_state.as_mut().unwrap();

        if !state.copy_player_inited {
            state.copy_player_inited = true;
            unsafe {
                write_volatile(
                    &mut state.copy_player as *mut Player,
                    read_volatile(&ctx.player as *const Player),
                );
            }
            state.current_player = &mut ctx.player as *mut Player;
            state.next_player = &mut state.copy_player as *mut Player;
        }

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
