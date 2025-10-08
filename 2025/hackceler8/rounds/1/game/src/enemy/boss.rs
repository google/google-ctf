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

use heapless::String;
use heapless::Vec;
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
use crate::resource_state::State;
use crate::Dialogue;
use core::fmt::Write;

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

#[derive(Clone)]
enum RegType {
    Control,
    Data,
}
pub struct BossDialogue {
    /// Params set during the boss dialogue:
    /// The list of registers that should be set and their data.
    reg_count: usize,
    regs: Vec<(RegType, u16), 100>,
}

impl BossDialogue {
    pub fn new() -> BossDialogue {
        BossDialogue {
            reg_count: 0,
            regs: Vec::new(),
        }
    }
}

pub fn dialogue(ctx: &mut Ctx) {
    let mut code = [0x4e71u16; 32];
    code[31] = 0x4e75;

    ctx.vdp.dma_upload_word_slice(0xC000, &code);

    ctx.boss_dialogue = BossDialogue::new();
    ctx.start_dialogue(Dialogue::new_free_text_restricted_charset(
        "GREETING MORTAL!\nYOU HAVE COME HERE IN VAIN, FOR I AM INVULNERABLE.\n\n\
         I CAN SET SOME REGISTERS FOR YOU THOUGH.\n\
         HOW MANY WILL YOU SET?",
        "0123456789",
        Some(get_reg_count),
    ));
}

fn get_reg_count(ctx: &mut Ctx, response: &str) {
    if let Some(count) = get_int(ctx, response, /*max=*/ 100, /*radix=*/ 10) {
        ctx.boss_dialogue.reg_count = count as usize;
        get_reg_params_1(ctx);
    }
}

fn get_reg_params_1(ctx: &mut Ctx) {
    let params = &mut ctx.boss_dialogue;
    if params.regs.len() >= params.reg_count {
        exec(ctx);
        return;
    }

    let mut text: String<32> = String::new();
    let _ = write!(text, "REG #{} TYPE:", params.regs.len());
    ctx.start_dialogue(Dialogue::new_multiple_choice(
        &text,
        &["Data", "Control"],
        Some(get_reg_params_2),
    ));
}

fn get_reg_params_2(ctx: &mut Ctx, response: &str) {
    let reg_type = if eq(response, "Data") {
        RegType::Data
    } else {
        RegType::Control
    };

    let params = &mut ctx.boss_dialogue;
    params
        .regs
        .push((reg_type, 0))
        .unwrap_or_else(|_| panic!("too many regs"));

    let mut text: String<32> = String::new();
    let _ = write!(text, "REG #{} VALUE:", params.regs.len() - 1);
    ctx.start_dialogue(Dialogue::new_free_text_restricted_charset(
        &text,
        "0123456789ABCDEF",
        Some(get_reg_params_3),
    ));
}

fn get_reg_params_3(ctx: &mut Ctx, response: &str) {
    let val = get_int(ctx, response, /*max=*/ 0xffff, /*radix=*/ 16);
    if val.is_none() {
        return;
    }

    ctx.boss_dialogue.regs.last_mut().unwrap().1 = val.unwrap() as u16;

    // Start over for the next register.
    get_reg_params_1(ctx);
}

fn exec(ctx: &mut Ctx) {
    ctx.start_dialogue(Dialogue::new_no_response(
        "BY MY DIVINE POWERS LET THESE REGISTERS BE SET!",
        Some(exec_2),
    ));
}

fn exec_2(ctx: &mut Ctx, _response: &str) {
    const REG_VDP_BASE: usize = 0x00c0_0000;
    const REG_VDP_DATA16: *mut u16 = REG_VDP_BASE as _;
    const REG_VDP_CONTROL16: *mut u16 = (REG_VDP_BASE + 4) as _;
    for (reg_type, val) in &ctx.boss_dialogue.regs {
        info!(
            "(RegType::{}, 0x{:x})",
            match reg_type {
                RegType::Data => "Data",
                RegType::Control => "Control",
            },
            *val,
        );
        let addr = match reg_type {
            RegType::Data => REG_VDP_DATA16,
            RegType::Control => REG_VDP_CONTROL16,
        };
        unsafe { core::ptr::write_volatile(addr, *val) }
    }

    let mut code = [0u16; 32];
    ctx.vdp.read_into_word_slice(0xC000, &mut code);
    // SAFETY: We initialized this memory region with valid code so this is safe.
    let func: extern "C" fn() = unsafe { core::mem::transmute(&code) };
    (func)();

    let mut still_alive = false;
    for e in &ctx.world.enemies {
        if e.is_boss() && e.is_alive() {
            still_alive = true;
            break;
        }
    }
    if still_alive {
        ctx.start_dialogue(Dialogue::new_no_response(
            "IT DOES NOT APPEAR THAT YOU MANAGED TO BEST ME. FAREWELL.",
            Some(lose),
        ));
    } else {
        ctx.start_dialogue(Dialogue::new_no_response(
            "IMPOSSIBLE, I HAVE BEEN DEFEATED!",
            None,
        ));
    }
}

fn get_int(ctx: &mut Ctx, string: &str, max: u16, radix: u32) -> Option<u16> {
    let int = u16::from_str_radix(string, radix);
    if !int.is_ok() {
        ctx.start_dialogue(Dialogue::new_no_response(
            "YOU HAVE FAILED ME MORTAL, THAT'S NOT AN INTEGER.",
            Some(lose),
        ));
        return None;
    }

    let int = int.unwrap();
    if int > max {
        ctx.start_dialogue(Dialogue::new_no_response(
            "YOU HAVE FAILED ME MORTAL, THAT'S TOO LARGE.",
            Some(lose),
        ));
        return None;
    }

    Some(int)
}

fn lose(ctx: &mut Ctx, _response: &str) {
    for player in &mut ctx.players {
        player.kill(/*falling=*/ false);
    }
}

fn eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.chars().zip(b.chars()).all(|(a, b)| a == b)
}
