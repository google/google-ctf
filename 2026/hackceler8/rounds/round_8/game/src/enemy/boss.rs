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
use crate::switch;
use crate::Dialogue;
use core::fmt::Write;
use core::ptr::read_volatile;
use heapless::String;

const SHOULD_BE_VULNERABLE: *mut char = 0xFF0503 as _;
const TEST_BYTE: *mut char = 0xFF0400 as _;

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
}

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
        BossState { explosion_sprites }
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
}

pub fn computer(ctx: &mut Ctx) {
    ctx.start_dialogue(Dialogue::new_multiple_choice(
        "BEEP BOOP!\nSELECT ACTION",
        &["Open door", "Sprite tiles"],
        Some(computer_2),
    ));
}

fn computer_2(ctx: &mut Ctx, response: &str) {
    if response == "Open door" {
        if ctx.map.get_enemies_destroyed_count() < 4 {
            ctx.start_dialogue(Dialogue::new_no_response(
                "YOU NEED TO DEFEAT THE 4 GUARDIANS FIRST",
                None,
            ));
        } else {
            ctx.start_dialogue(Dialogue::new_no_response("OPENING DOOR", None));
            switch::open_door_0(ctx);
        }
        return;
    }

    ctx.start_dialogue(Dialogue::new_free_text_restricted_charset(
        "WHICH SPRITE OFFSET DO YOU WANT TO START WITH?",
        "0123456789",
        Some(computer_3),
    ));
}

fn computer_3(ctx: &mut Ctx, response: &str) {
    let offs = u8::from_str_radix(response, 10);
    if offs.is_err() {
        ctx.start_dialogue(Dialogue::new_no_response("INVALID OFFSET", None));
        return;
    }
    let offs = offs.unwrap();
    // Instructions need to align to 16 bits.
    if offs % 2 != 0 {
        ctx.start_dialogue(Dialogue::new_no_response("INVALID OFFSET", None));
        return;
    }

    let mut sprite_buf = [0u16; 64];
    ctx.vdp.get_sprite_buf(&mut sprite_buf);

    let mut cmd_buf = [0u16; 64];
    // Initialize with NOPs.
    for i in 0..64 {
        cmd_buf[i] = 0x4e71;
    }

    // Initialize counter reg.
    cmd_buf[0] = 0x4280;

    // Jump to the specified offset so we only count those sprites.
    cmd_buf[1] = 0x6000 | (offs + 2) as u16;

    for i in 0..16 {
        // Compute the sprite size in tiles.
        // SAFETY: This data was taken directly from the sprite VRAM so it's guaranteed to be
        // a valid SpriteSize enum.
        let size: SpriteSize = unsafe { core::mem::transmute((sprite_buf[i * 4 + 1] >> 8) as u8) };
        let size_tiles = (SpriteSize::w(size) * SpriteSize::h(size)) as u16;

        if size_tiles <= 8 {
            // Increment the counter by the size amount.
            cmd_buf[i * 2 + 3] = 0x5080 | (size_tiles & 7) << 9;
        } else {
            // Quick increments don't support adding more than 8
            // so we use two instructions.
            cmd_buf[i * 2 + 3] = 0x5080 | ((size_tiles - 8) & 7) << 9;
            cmd_buf[i * 2 + 4] = 0x5080;
        }
    }

    // Return.
    cmd_buf[63] = 0x4e75;

    unsafe {
        read_volatile(TEST_BYTE);
    }

    // SAFETY: We fill the buffer with a limited range of benign instructions.
    let func: extern "C" fn() -> u32 = unsafe { core::mem::transmute(&cmd_buf) };
    let count = (func)();

    let mut msg: String<128> = String::new();
    let _ = write!(
        msg,
        "The sprites on screen occupy {} tiles in total.",
        count
    );
    ctx.start_dialogue(Dialogue::new_no_response(&msg, None));
}
