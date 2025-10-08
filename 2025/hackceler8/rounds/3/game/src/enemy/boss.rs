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

use core::fmt::Write;
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
use heapless::String;

#[no_mangle]
static mut BOSS_DATA_BUF: [u8; 0xFF1000 - 0xFF0100] = [0; 0xFF1000 - 0xFF0100];

const PLAYER_COUNT: usize = 4;
/// 8 bytes per player name.
const PLAYER_NAME_LEN: usize = 8;
/// 8 bytes worth of kills (= 64 enemies) stored per player.
const PLAYER_KILLS_LEN: usize = 8;
/// BOSS_DATA_BUF sections:
/// Player names. Stored in a compressed format.
const PLAYER_NAMES_ADDR: usize = 0xFF0100;
/// Starting address of the kills - it's randomized per gameplay.
const KILLS_START_ADDR: usize = PLAYER_NAMES_ADDR + PLAYER_COUNT * PLAYER_NAME_LEN;
/// The kills buffer - player kills are stored here from a random start offset.
const KILLS_BUF_ADDR: usize = KILLS_START_ADDR + 4;
/// We'll write PLAYER_COUNT * PLAYER_KILLS_LEN bytes somewhere between KILLS_BUF_ADDR and the heap start.
const KILLS_BUF_MAX_OFFS: usize = 0xFF1000 - KILLS_BUF_ADDR - PLAYER_COUNT * PLAYER_KILLS_LEN;

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

pub struct BossData {
    /// Player name lengths.
    player_name_len: [usize; PLAYER_COUNT],
    /// Minions killed by each player.
    kill_count: [usize; PLAYER_COUNT],
    /// Starting offset of the kills. Randomized per gameplay.
    kills_offs: usize,

    /// Temporary values used for dialogue menus:

    /// String used to display kills.
    display_text: String<4096>,
    /// Number of lines from the kill text already displayed.
    displayed_lines: usize,
    /// The ID of the player currently being renamed.
    renamed_player_id: usize,
}

impl BossData {
    pub fn new(ctx: &mut Ctx) -> BossData {
        // Randomize the kill buffer position once per game.
        if ctx.boss_kills_offs.is_none() {
            ctx.boss_kills_offs = Some(ctx.portal.get_random_int() as usize % (KILLS_BUF_MAX_OFFS));
        }
        let kills_offs = ctx.boss_kills_offs.unwrap();

        // SAFETY: I'm a security engineer and I know what I'm doing.
        unsafe {
            // Clear previous data and save start address.
            let kills = KILLS_BUF_ADDR as *mut u8;
            core::ptr::write(KILLS_START_ADDR as *mut u32, kills as u32);
            kills
                .offset(kills_offs as isize)
                .write_bytes(0, PLAYER_COUNT * PLAYER_KILLS_LEN);

            // Also init the player name data.
            let player_names = PLAYER_NAMES_ADDR as *mut u8;
            player_names.write_bytes(0, PLAYER_COUNT * PLAYER_NAME_LEN);
            for i in 0..PLAYER_COUNT {
                player_names
                    .offset((i * PLAYER_NAME_LEN) as isize)
                    .write(0xf0 + i as u8); // Compressed form of "PA", "PB", "PC", "PD"
            }
        }

        BossData {
            player_name_len: [1; PLAYER_COUNT],
            kill_count: [0; PLAYER_COUNT],
            kills_offs,
            display_text: String::new(),
            displayed_lines: 0,
            renamed_player_id: 0,
        }
    }
}

pub fn record_minion_kill(ctx: &mut Ctx, player_id: usize, enemy_type: EnemyType) {
    if ctx.boss_data.is_none() {
        return;
    }
    let data = ctx.boss_data.as_mut().unwrap();

    if data.kill_count[player_id] >= PLAYER_KILLS_LEN * 8 {
        // Max kill count reached.
        return;
    }

    // Store kills as a bitfield.
    // OrcMinion = 0, AngelMinion = 1
    let kills = unsafe {
        (core::ptr::read(KILLS_START_ADDR as *mut u32) as *mut u8).offset(
            // The randomized offset
            (data.kills_offs
             // Start of the given player's kills
             + player_id * PLAYER_KILLS_LEN) as isize
                // Current byte in the bitfield
                + (data.kill_count[player_id] >> 3) as isize,
        )
    };
    let mut byte = unsafe { kills.read() };
    let exp = 7 - data.kill_count[player_id] % 8;
    let bit = if enemy_type == EnemyType::AngelMinion {
        1
    } else {
        0
    };
    byte &= !(1 << exp);
    byte |= bit << exp;
    unsafe { kills.write(byte) };
    data.kill_count[player_id] += 1;
}

pub fn computer() -> Dialogue {
    Dialogue::new_multiple_choice(
        "BEEP BOOP!\nSELECT ACTION:",
        &["Set names", "View kills"],
        Some(computer_2),
    )
}

fn computer_2(ctx: &mut Ctx, response: &str) {
    if eq(response, "Set names") {
        set_names(ctx);
    } else {
        list_kills(ctx);
    }
}

fn set_names(ctx: &mut Ctx) {
    ctx.start_dialogue(Dialogue::new_multiple_choice(
        "SELECT PLAYER:",
        &["P1", "P2", "P3", "P4"],
        Some(set_names_2),
    ));
}

fn set_names_2(ctx: &mut Ctx, response: &str) {
    if ctx.boss_data.is_none() {
        return;
    }
    let data = ctx.boss_data.as_mut().unwrap();

    data.renamed_player_id = if eq(response, "P1") {
        0
    } else if eq(response, "P2") {
        1
    } else if eq(response, "P3") {
        2
    } else {
        3
    };
    ctx.start_dialogue(Dialogue::new_free_text_restricted_charset(
        "NEW NAME:",
        "ABCDEFGHIJKLMNOP",
        Some(set_names_3),
    ));
}

fn set_names_3(ctx: &mut Ctx, response: &str) {
    if ctx.boss_data.is_none() {
        return;
    }
    let data = ctx.boss_data.as_mut().unwrap();

    if response.len() % 2 != 0 {
        ctx.start_dialogue(Dialogue::new_no_response("ERROR: NAME MISALIGNED", None));
        return;
    }

    data.player_name_len[data.renamed_player_id] = response.len() / 2;
    // Store player name in a compressed format (every 2 letters compressed into 1 byte).
    for i in 0..response.len() / 2 {
        let byte_to_store = compress(
            response.chars().nth(i * 2).unwrap(),
            response.chars().nth(i * 2 + 1).unwrap(),
        );
        unsafe {
            let player_name = (PLAYER_NAMES_ADDR as *mut u8)
                .offset((data.renamed_player_id * PLAYER_NAME_LEN + i) as isize);
            player_name.write(byte_to_store);
        }
    }
    let mut text: String<64> = String::new();
    let _ = write!(
        text,
        "RENAMED P{} to {}!",
        data.renamed_player_id + 1,
        response,
    );
    ctx.start_dialogue(Dialogue::new_no_response(&text, None));
}

/// Compress two letters of the player name (always between 'A' - 'P') into a single byte.
fn compress(char_1: char, char_2: char) -> u8 {
    ((char_1 as u8 - b'A') << 4) | (char_2 as u8 - b'A')
}

fn uncompress(byte: u8) -> (char, char) {
    (((byte >> 4) + b'A') as char, ((byte & 0xf) + b'A') as char)
}

fn list_kills(ctx: &mut Ctx) {
    if ctx.boss_data.is_none() {
        return;
    }
    let data = ctx.boss_data.as_mut().unwrap();

    data.display_text = String::new();
    data.displayed_lines = 0;
    for p in 0..PLAYER_COUNT {
        let player_names = PLAYER_NAMES_ADDR as *mut u8;
        for i in 0..data.player_name_len[p] {
            // Player names are stored compressed so we need to uncompress it.
            let compressed_char = unsafe {
                player_names
                    .offset((p * PLAYER_NAME_LEN + i) as isize)
                    .read() as char
            };
            let (char_1, char_2) = uncompress(compressed_char as u8);
            data.display_text.push(char_1).unwrap();
            data.display_text.push(char_2).unwrap();
        }
        data.display_text.push_str(":\n").unwrap();
        if data.kill_count[p] == 0 {
            data.display_text.push_str("No kills\n").unwrap();
        } else {
            for k in 0..data.kill_count[p] {
                data.display_text
                    .push_str(get_kill_name(data, p, k))
                    .unwrap();
                data.display_text.push_str("\n").unwrap();
            }
        }
    }
    display_kills(ctx, "");
}

const ANGEL_MINION: &str = "Angel minion";
const ORC_MINION: &str = "Orc minion";

fn get_kill_name(data: &BossData, player_id: usize, kill_num: usize) -> &'static str {
    // Kills are stored in a bitfield - this reads the bit for the given player at the given pos.
    let kills = unsafe {
        (core::ptr::read(KILLS_START_ADDR as *mut u32) as *mut u8).offset(
            // The randomized offset
            (data.kills_offs
             // Start of the given player's kills
             + player_id * PLAYER_KILLS_LEN) as isize
            // Current byte in the bitfield
                + (kill_num >> 3) as isize,
        )
    };
    let byte = unsafe { kills.read() };
    if byte & 1 << (7 - kill_num % 8) > 0 {
        return ANGEL_MINION;
    }
    ORC_MINION
}

fn display_kills(ctx: &mut Ctx, _response: &str) {
    if ctx.boss_data.is_none() {
        return;
    }
    let data = ctx.boss_data.as_mut().unwrap();

    // Dialogues can only display TEXT_HEIGHT number of lines at a time,
    // so we split the text into multiple dialogues.
    let portion = get_text_portion(
        &data.display_text,
        data.displayed_lines,
        data.displayed_lines + dialogue::TEXT_HEIGHT as usize,
    );
    data.displayed_lines += dialogue::TEXT_HEIGHT as usize;
    if portion.len() == 0 {
        return;
    }

    // Copy over to avoid double borrowing ctx.
    let mut portion_copy: String<320> = String::new();
    portion_copy.push_str(portion).unwrap();
    ctx.start_dialogue(Dialogue::new_no_response(
        &portion_copy,
        Some(display_kills),
    ));
}

/// Get the portion of the text between the line numbers specified,
/// or an empty string if there are no more lines left.
fn get_text_portion(text: &str, line_start: usize, line_end: usize) -> &str {
    let mut start = 0;
    let mut line_count = 0;
    for i in 0..text.len() {
        start = i;
        if line_count == line_start {
            break;
        }
        if text.chars().nth(i).unwrap() == '\n' {
            line_count += 1;
        }
    }

    let mut end = start;
    for i in start + 1..text.len() {
        end = i;
        if line_count == line_end {
            break;
        }
        if text.chars().nth(i).unwrap() == '\n' {
            line_count += 1;
        }
    }

    &text[start..end]
}

fn eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.chars().zip(b.chars()).all(|(a, b)| a == b)
}
