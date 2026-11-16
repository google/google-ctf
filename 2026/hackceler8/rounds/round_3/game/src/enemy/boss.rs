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
use crate::res::enemies::EnemyType;
use crate::res::sprites::boss::Anim;
use crate::res::sprites::explosion as ExplosionSprite;
use crate::resource_state::State;
use crate::Bitmask;
use crate::Map;
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
        melee: false,
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

const MAZES_LEN: usize = 4;

/// Boss related enemy state data.
pub struct BossState {
    /// Explosions for the boss death sequence.
    explosion_sprites: [BigSprite; 2],
    pub mazes: [[u16; 64]; MAZES_LEN],
    pub next_maze_offs: i16,
    pub current_maze: u16,
}

impl BossState {
    pub fn new(res_state: &mut State, vdp: &mut TargetVdp, frame: u32) -> BossState {
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
        // Randomize the starting maze and the next one based on the current game frame.
        let current_maze = (frame % 4) as u16;
        let next_maze_offs = get_next_maze_offs(current_maze, frame);
        BossState {
            explosion_sprites,
            mazes: data::boss_maze(),
            next_maze_offs,
            current_maze,
        }
    }

    /// Returns whether there's a wall in the currently active maze at the given position.
    pub fn is_maze_wall_at(&self, x: usize, y: usize) -> bool {
        // Wall bits are set to 0.
        // We use direct access for faster execution since this function is often called.
        // SAFETY: The indexes are always set to be within the array range.
        return unsafe {
            let ptr: *const u16 = transmute(&self.mazes);
            read_volatile(ptr.offset((self.current_maze as usize * data::MAZE_W + x) as isize))
        } & (1 << y)
            != 0;
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
    }

    pub fn load_next_maze(ctx: &mut Ctx) {
        if ctx.map.boss_state.is_none() {
            return;
        }

        let state = ctx.map.boss_state.as_mut().unwrap();

        // next_maze_offs measures the offset from the end of the maze array.
        state.current_maze = (MAZES_LEN as i16 + state.next_maze_offs) as u16;
        state.next_maze_offs = get_next_maze_offs(state.current_maze, ctx.map.play_frame);

        // Reset the switch so it can be hit again in the next maze run.
        ctx.map.switches_completed = Bitmask::new();
        for switch in &mut ctx.map.switches {
            switch.reset();
        }

        // Move player back to the spawn location and update map scroll.
        let px = ctx.map.map_data.player_spawn_position.0 - ctx.map.scroll_offset.0 + 128;
        let py = ctx.map.map_data.player_spawn_position.1 - ctx.map.scroll_offset.1 + 128;
        let center: (i16, i16) = ctx.player.hitbox().center();
        ctx.player.move_relative(px - center.0, py - center.1);
        ctx.map.boss_maze_resetting = true;
        Map::maybe_scroll_map(ctx);
        ctx.map.boss_maze_resetting = false;
        ctx.map.redraw(&mut ctx.vdp, &mut ctx.res_state);
        ctx.player.move_to_ground(&ctx.map);
    }

    pub fn destroy_maze_tiles(ctx: &mut Ctx, hurtbox: &Hitbox) {
        if ctx.map.boss_state.is_none() {
            return;
        }

        let state = ctx.map.boss_state.as_mut().unwrap();

        let start_x = (hurtbox.x - 128 + ctx.map.scroll_offset.0) / 8;
        let end_x = start_x + hurtbox.w / 8 + 1;
        let start_y = (hurtbox.y - 128 + ctx.map.scroll_offset.1) / 8;
        let end_y = start_y + hurtbox.h / 8 + 1;

        for y in start_y..end_y {
            if y < data::MAZE_START_Y as i16 || y >= (data::MAZE_START_Y + data::MAZE_H) as i16 {
                continue;
            }
            let maze_y = y as usize - data::MAZE_START_Y;
            for x in start_x..end_x {
                if x < data::MAZE_START_X as i16 || x > (data::MAZE_START_X + data::MAZE_W) as i16 {
                    continue;
                }
                let maze_x = x as usize - data::MAZE_START_X;

                // Wall bits are set to 1. Destroy them by setting them to 0.
                // We use direct access for faster execution.
                // SAFETY: The indexes are always set to be within the array range.
                unsafe {
                    let mut ptr: *mut u16 = transmute(&state.mazes);
                    ptr =
                        ptr.offset((state.current_maze as usize * data::MAZE_W + maze_x) as isize);
                    let val = read_volatile(ptr);
                    write_volatile(ptr, val & !(1 << maze_y));
                }
            }
        }
        ctx.map.map_data.reload_tiles(
            &mut ctx.vdp,
            &mut ctx.res_state,
            ctx.map.scroll_offset,
            ctx.map.plane_window.vram_address(),
            &ctx.map.boss_state,
            start_x,
            end_x,
            start_y,
            end_y,
        );
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

pub fn get_next_maze_offs(current_maze: u16, frame: u32) -> i16 {
    let mut next = (frame / 4) as u16 % MAZES_LEN as u16;
    if next == current_maze {
        // Make sure we switch to a different maze than the previous one.
        next = (next + 1) % MAZES_LEN as u16;
    }
    // the next maze offset measures the offset from the end of the maze array.
    (next as i16) - MAZES_LEN as i16
}
