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
use crate::dialogue;
use crate::enemy;
use crate::enemy::EnemyImpl;
use crate::enemy::Status;
use crate::entity::*;
use crate::game::Ctx;
use crate::res::enemies::EnemyType;
use crate::res::sprites::explosion as ExplosionSprite;
use crate::resource_state::State;
use crate::Dialogue;

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

/// Boss related enemy state data.
pub struct BossState {
    /// Explosions for the boss death sequence.
    explosion_sprites: [BigSprite; 2],
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
        BossState { explosion_sprites }
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
        let boss = boss.unwrap();

        for sprite in &mut state.explosion_sprites {
            sprite.update();
        }

        // Update explosion positions for the boss defeat sequence.
        if let Status::Dying {
            falling: _,
            cooldown,
        } = boss.status
        {
            let center = boss.hitbox().center();
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
    }

    pub fn render(&mut self, renderer: &mut TargetRenderer) {
        for sprite in &mut self.explosion_sprites {
            sprite.render(renderer);
        }
    }
}

pub struct BossDialogue {
    /// The offset to write the buffer data from.
    write_offs: usize,
}

impl BossDialogue {
    pub fn new() -> BossDialogue {
        BossDialogue { write_offs: 0 }
    }
}

pub fn dialogue(ctx: &mut Ctx) {
    ctx.start_dialogue(Dialogue::new_free_text_restricted_charset(
        "GREETING MORTAL!\nYOU HAVE COME HERE IN VAIN, FOR I AM INVULNERABLE.\n\n\
         I CAN STORE YOUR DATA IN A BUFFER THOUGH.\n\
         WHAT WILL THE STARTING OFFSET BE?",
        "0123456789",
        Some(dialogue_2),
    ));
}

const BUF_LEN: usize = 1024;

fn dialogue_2(ctx: &mut Ctx, response: &str) {
    let offs = usize::from_str_radix(&response, 10);
    if !offs.is_ok() {
        ctx.start_dialogue(Dialogue::new_no_response(
            "THAT'S NOT A VALID BYTE, MORTAL.",
            None,
        ));
        return;
    }
    let offs = offs.unwrap();
    // One byte per 2 chars
    let max_data_len = (dialogue::TEXT_WIDTH / 2) as usize;
    if offs >= BUF_LEN - max_data_len {
        ctx.start_dialogue(Dialogue::new_no_response(
            "THAT'S TOO LARGE FOR AN OFSET.",
            None,
        ));
        return;
    }

    ctx.boss_dialogue.write_offs = offs;
    ctx.start_dialogue(Dialogue::new_free_text_restricted_charset(
        "NOW TELL ME THE DATA TO SET.",
        "0123456789ABCDEF",
        Some(dialogue_3),
    ));
}

fn dialogue_3(ctx: &mut Ctx, response: &str) {
    unsafe { core::ptr::read_volatile(0x123456 as *const u16) };
    if response.len() % 2 != 0 {
        ctx.start_dialogue(Dialogue::new_no_response(
            "YOUR BYTES ARE MISALIGNED, MORTAL.",
            None,
        ));
        return;
    }

    let mut buf = [0u8; BUF_LEN];
    let buf_ptr = buf.as_mut_ptr() as *mut u32;
    let write_start = unsafe { buf_ptr.offset(ctx.boss_dialogue.write_offs as isize) };
    for i in 0..response.len() / 2 {
        let byte = u8::from_str_radix(&response[i * 2..i * 2 + 2], 16);
        if !byte.is_ok() {
            ctx.start_dialogue(Dialogue::new_no_response(
                "THAT'S NOT A VALID BYTE, MORTAL.",
                None,
            ));
            return;
        }
        let byte = byte.unwrap();
        // Set the buffer through raw addressing for better performance.
        // SAFETY: We check for overflows so this is safe.
        unsafe {
            core::ptr::write_volatile((write_start as *mut u8).offset(i as isize), byte);
        }
    }
    info!("Wrote bytes to buffer!");
    ctx.boss_dialogue = BossDialogue::new();
}
