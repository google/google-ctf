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
use crate::res::sprites::explosion as ExplosionSprite;
use crate::res::sprites::swirl as SwirlSprite;
use crate::resource_state::State;

pub(crate) fn new() -> EnemyImpl {
    EnemyImpl {
        stats,
        update_animation,
    }
}

fn stats(_enemy_type: EnemyType) -> Stats {
    Stats {
        speed: 16,
        health: 25,
        strength: 1,
        melee: true,
        shoots: false,
        sings: false,
        tracks: false,
        flies: false,
        hitbox: Hitbox {
            x: 12,
            y: 16,
            w: 104,
            h: 80,
        },
    }
}

fn update_animation(_enemy: &mut Enemy, _walking: bool) {}

pub fn should_render_sprite(enemy: &mut Enemy) -> bool {
    match enemy.status {
        Status::Dying {
            falling: _,
            cooldown,
            // Flash on and off in the  first half, then keep the flash o
            // for the second half of the death sequence.
        } => cooldown > enemy::BOSS_DEATH_COOLDOWN / 2 || (cooldown / 10) % 2 == 0,
        Status::KnockedBack {
            direction: _,
            cooldown,
        } => cooldown >= enemy::KNOCKBACK_COOLDOWN - 6,
        _ => false,
    }
}

/// We store at most 4 positions per player (x and y, 1 byte each).
/// Make this 8 to be safe.
const POS_MAX_COUNT: usize = 8;
const POS_BUF_LEN: usize = 4 * 2 * POS_MAX_COUNT;

/// Boss related enemy state data.
pub struct BossState {
    /// Explosions for the boss death sequence.
    explosion_sprites: [BigSprite; 2],
    swirl_sprite: BigSprite,
    frame: u16,
    /// Stores saved player positions for the 4 players.
    buffer: [u8; POS_BUF_LEN + 32],
    /// Number of stored positions for the 4 players.
    stored_pos_count: [usize; 4],
}

impl BossState {
    pub fn new(res_state: &mut State, vdp: &mut TargetVdp) -> BossState {
        let mut explosion_sprites = [
            ExplosionSprite::new(res_state, vdp, /* keep_loaded= */ false),
            ExplosionSprite::new(res_state, vdp, /* keep_loaded= */ false),
        ];
        for sprite in &mut explosion_sprites {
            sprite.set_anim(ExplosionSprite::Anim::Explode as usize);
        }
        let mut swirl_sprite = SwirlSprite::new(res_state, vdp, /* keep_loaded= */ false);
        swirl_sprite.set_anim(SwirlSprite::Anim::Off as usize);

        let mut buffer = [0; POS_BUF_LEN + 32];
        for i in POS_BUF_LEN..POS_BUF_LEN + 30 {
            buffer[i] = if i % 2 == 0 { 0x4e } else { 0x71 };
        }
        buffer[POS_BUF_LEN + 30] = 0x4e;
        buffer[POS_BUF_LEN + 31] = 0x75;

        BossState {
            explosion_sprites,
            swirl_sprite,
            frame: 0,
            buffer,
            stored_pos_count: [0; 4],
        }
    }

    fn peek_pos(&mut self, p: usize) -> Option<(i16, i16)> {
        if self.stored_pos_count[p] == 0 {
            return None;
        }

        let idx = POS_MAX_COUNT * 2 * p + self.stored_pos_count[p] * 2 - 2;
        Some(Self::bytes_to_pos(self.buffer[idx], self.buffer[idx + 1]))
    }

    fn pop_pos(&mut self, p: usize) -> Option<(i16, i16)> {
        let pos = self.peek_pos(p);
        if pos.is_some() {
            self.stored_pos_count[p] -= 1;
        }
        pos
    }

    fn push_pos(&mut self, p: usize, x: i16, y: i16) {
        let (x_byte, y_byte) = Self::pos_to_bytes(x, y);
        let idx = POS_MAX_COUNT * 2 * p + self.stored_pos_count[p] * 2;
        self.stored_pos_count[p] += 1;

        self.buffer[idx] = x_byte;
        self.buffer[idx + 1] = y_byte;
        info!("push {:x} {:x}", x_byte, y_byte);
    }

    // Full player positions don't fit into u8 so we just store the
    // range the player can walk across on the boss map.
    const X_OFFS: i16 = 152;
    const Y_OFFS: i16 = 129;

    fn pos_to_bytes(x: i16, y: i16) -> (u8, u8) {
        let x = (x - Self::X_OFFS).max(0).min(0xff) as u8;
        let mut y = (y - Self::Y_OFFS).max(0).min(0xff) as u8;

        // Saturate y position.
        if y >= 0xc3 {
            y = 0xff
        }

        (x, y)
    }

    fn bytes_to_pos(x_byte: u8, mut y_byte: u8) -> (i16, i16) {
        // Unsaturate y position.
        if y_byte == 0xff {
            y_byte = 0xc3
        }
        (x_byte as i16 + Self::X_OFFS, y_byte as i16 + Self::Y_OFFS)
    }

    pub fn update(ctx: &mut Ctx) {
        if ctx.world.boss_state.is_none() {
            return;
        }
        let state = ctx.world.boss_state.as_mut().unwrap();

        let boss = ctx.world.enemies.iter_mut().find(|e| e.is_boss());
        if boss.is_none() {
            return;
        }
        let boss = boss.as_ref().unwrap();

        for sprite in &mut state.explosion_sprites {
            sprite.update();
        }
        state.swirl_sprite.update();

        let center = boss.hitbox().center();
        // Update explosion positions for the boss defeat sequence.
        if let Status::Dying {
            falling: _,
            cooldown,
        } = boss.status
        {
            for (i, sprite) in state.explosion_sprites.iter_mut().enumerate() {
                // Start new explosions at random positions with a phase shift between the two sprites.
                let explosion_frame = cooldown as usize + 15 * i;
                if explosion_frame % 30 == 1 {
                    let (dx, dy) = data::EXPLOSION_OFFSETS[i][explosion_frame / 30];
                    sprite.set_position(center.0 - 8 + dx, center.1 - 8 + dy);
                    sprite.set_anim(ExplosionSprite::Anim::Explode as usize);
                }
            }
        }
        state
            .swirl_sprite
            .set_position(center.0 - 16, center.1 - 16);

        // Battle logic
        if !boss.is_alive() || ctx.players.iter().all(|p| !p.active || p.is_dead()) {
            return;
        }

        // Save boss so we don't forget about it.
        unsafe {
            core::ptr::write_volatile((0xffffb4) as *mut u32, *boss as *const _ as u32);
        }

        for p in 0..ctx.players.len() {
            let player = &mut ctx.players[p];
            if !player.can_be_targeted() {
                continue;
            }
            if state.frame % 350 < 200 {
                // First 4s: Store the player's position every 1s.
                if state.frame % 50 == 0 {
                    state.push_pos(p, player.x, player.y);
                    state
                        .swirl_sprite
                        .set_anim(SwirlSprite::Anim::Flash as usize);
                }
            } else if state.frame % 350 < 300 {
                // Next 2s: Move the player back to a previous position every 0.5s.
                // This empties the position queue.
                let pos = if state.frame % 25 == 24 {
                    state.pop_pos(p)
                } else {
                    state.peek_pos(p)
                };
                if let Some((x, y)) = pos {
                    player.set_position(x, y);
                }
                state
                    .swirl_sprite
                    .maybe_set_anim(SwirlSprite::Anim::Swirl as usize);
            } else {
                // Next 1s: Idle
                state
                    .swirl_sprite
                    .maybe_set_anim(SwirlSprite::Anim::Stop as usize);
            }
        }

        state.frame = state.frame.wrapping_add(1);
    }

    pub fn render(&mut self, renderer: &mut TargetRenderer) {
        for sprite in &mut self.explosion_sprites {
            sprite.render(renderer);
        }
        self.swirl_sprite.render(renderer);
    }
}

pub fn run_code(ctx: &mut Ctx) {
    if ctx.world.boss_state.is_none() {
        return;
    }
    let state = ctx.world.boss_state.as_mut().unwrap();

    // Run NOP sled code that's stored after the positions.
    // SAFETY: We have extra buffer space so this should be okay to do.
    let func: extern "C" fn() = unsafe { core::mem::transmute(&state.buffer[POS_BUF_LEN]) };
    (func)();
}
