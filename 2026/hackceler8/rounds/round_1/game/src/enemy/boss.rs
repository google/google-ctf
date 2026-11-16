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

use core::fmt::Write;
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
use crate::Dialogue;
use core::ptr::read_volatile;
use heapless::String;

const SHOULD_BE_VULNERABLE: *mut char = 0xFF0008 as _;

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
    if unsafe { read_volatile(SHOULD_BE_VULNERABLE) } as u8 == 'Y' as u8 {
        enemy.invulnerable = false;
    }
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
    pub buffer: [u16; 32],
    pub kills_left: usize,
}

/// We record at most this many minion positions in the kill buffer.
const MAX_KILLS: usize = 16;

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

        let mut buffer = [0u16; 32];
        // Add NOP sled to the end of the buffer.
        for i in 0..31 {
            buffer[i] = 0x4e71;
        }
        buffer[31] = 0x4e75;

        BossState {
            explosion_sprites,
            buffer,
            kills_left: MAX_KILLS,
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

    pub fn record_kill(&mut self, enemy: &mut Enemy) {
        let pos = MAX_KILLS - self.kills_left;

        self.kills_left -= 1;
        let x = (enemy.x - 188).max(0).min(255) as u8;
        let y = (enemy.y - 188).min(255) as u8;
        self.buffer[pos] = ((x as u16) << 8) | y as u16;

        info!("kill #{}: {},{}", pos, enemy.x, enemy.y);
    }
}

pub fn computer(ctx: &mut Ctx) {
    ctx.start_dialogue(Dialogue::new_multiple_choice(
        "BEEP BOOP!\nSELECT ACTION:",
        &["View kills", "Run NOPs"],
        Some(computer_2),
    ));
}

fn computer_2(ctx: &mut Ctx, response: &str) {
    if response == "View kills" {
        view_kills(ctx);
    } else {
        run_nops(ctx);
    }
}

fn view_kills(ctx: &mut Ctx) {
    if ctx.map.boss_state.is_none() {
        return;
    }
    let state = ctx.map.boss_state.as_mut().unwrap();
    let total = MAX_KILLS - state.kills_left;
    let mut corner_count = [0u16; 4];
    for i in 0..total {
        let x = state.buffer[i] & 0xff;
        let y = state.buffer[i] >> 8;
        let corner = if x < 160 {
            if y < 112 {
                0 // upper left
            } else {
                1 // lower left
            }
        } else {
            if y < 112 {
                2 // upper right
            } else {
                3 // lower right
            }
        };
        corner_count[corner] += 1;
    }
    let mut msg: String<128> = String::new();
    let _ = write!(msg, "Kill stats:\n{} in upper left corner\n{} in lower left corner\n{} in upper right corner\n{} in lower right corner", corner_count[0], corner_count[1], corner_count[2], corner_count[3]);
    ctx.start_dialogue(Dialogue::new_no_response(&msg, None));
}

fn run_nops(ctx: &mut Ctx) {
    ctx.start_dialogue(Dialogue::new_no_response(
        "Running NOP sled!",
        Some(run_nops_2),
    ));
}

fn run_nops_2(ctx: &mut Ctx, _: &str) {
    if ctx.map.boss_state.is_none() {
        return;
    }
    let state = ctx.map.boss_state.as_mut().unwrap();

    // SAFETY: We have a check to prevent code in this region fromm being overwritten.
    let func: extern "C" fn() = unsafe { core::mem::transmute(&state.buffer[17]) };
    (func)();
}
