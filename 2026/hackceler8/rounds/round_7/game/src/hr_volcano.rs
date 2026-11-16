// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use megahx8::*;

use crate::game::{challenge_id, Ctx};
use crate::res::maps::MapType;

const VOLCANO_STAGE_APPROVED: i64 = 1;
const VOLCANO_STAGE_FILED: i64 = 2;

#[repr(C, align(4))]
pub struct VolcanoDossierState {
    pub streak: u16,
    pub calls: u16,
    pub solved: u16,
    pub pad0: u16,
    pub buf_len: u16,
    pub pad1: [u16; 3],
    pub altar: u16,
    pub pad2: u16,
    pub docked: u16,
    pub pad3: u16,
    pub prev_pad: u16,
    pub pad4: [u16; 3],
    pub kpi_table: [u16; 3],
    pub tenure_gate: u16,
    pub scratch_word: u16,
    pub pad5: [u16; 19],
    pub chord_buf: [u16; 8],
}

impl VolcanoDossierState {
    pub(crate) const fn new() -> Self {
        Self {
            streak: 0,
            calls: 0,
            solved: 0,
            pad0: 0,
            buf_len: 0,
            pad1: [0; 3],
            altar: 0,
            pad2: 0,
            docked: 0,
            pad3: 0,
            prev_pad: 0,
            pad4: [0; 3],
            kpi_table: [0; 3],
            tenure_gate: 1,
            scratch_word: 0,
            pad5: [0; 19],
            chord_buf: [0; 8],
        }
    }
}

pub static mut VOLCANO_STATE: VolcanoDossierState = VolcanoDossierState::new();
pub static mut HR_HUD_CACHE: u32 = u32::MAX;
static mut VOLCANO_RECORDED: bool = false;

#[inline(always)]
pub fn volcano_state_base() -> i64 {
    core::ptr::addr_of_mut!(VOLCANO_STATE) as usize as i64
}

extern "C" {
    pub(crate) fn hr_volcano_init(base: i64);
    pub(crate) fn hr_evaluate_performance(
        base: i64,
        frame: i64,
        player_x: i64,
        player_y: i64,
        pad: i64,
    ) -> i64;
}


pub(crate) fn on_load_map(new_map: MapType) {
    unsafe {
        core::ptr::write_volatile(&raw mut HR_HUD_CACHE, u32::MAX);
        if matches!(new_map, MapType::Volcano) {
            core::ptr::write_volatile(&raw mut VOLCANO_RECORDED, false);
            hr_volcano_init(volcano_state_base());
        }
    }
}

fn pack_controller_mask<C: Controllers>(controller: &C) -> i64 {
    let Some(state) = controller.controller_state(0) else {
        return 0;
    };
    const BUTTONS: [Button; 12] = [
        Button::Up,
        Button::Down,
        Button::Left,
        Button::Right,
        Button::B,
        Button::C,
        Button::A,
        Button::Start,
        Button::Z,
        Button::Y,
        Button::X,
        Button::Mode,
    ];
    let mut mask = 0i64;
    for btn in BUTTONS {
        if state.is_pressed(btn) {
            mask |= 1i64 << (btn as u8);
        }
    }
    mask
}

pub(crate) fn update(ctx: &mut Ctx) {
    if !matches!(ctx.map.map_type, MapType::Volcano) {
        unsafe {
            core::ptr::write_volatile(&raw mut HR_HUD_CACHE, u32::MAX);
        }
        return;
    }

    let pad_mask = pack_controller_mask(&ctx.controller);
    let solved = unsafe {
        hr_evaluate_performance(
            volcano_state_base(),
            ctx.score_frame as i64,
            (ctx.player.x + ctx.map.scroll_offset.0) as i64,
            ctx.player.y as i64,
            pad_mask,
        )
    };

    if matches!(solved, VOLCANO_STAGE_APPROVED | VOLCANO_STAGE_FILED) {
        for door in &mut ctx.map.doors {
            door.unlock();
            door.open();
            ctx.map.doors_unlocked.set(door.id);
            ctx.map.doors_locked.clear(door.id);
        }
        for switch in &mut ctx.map.switches {
            switch.pending = true;
        }
        for enemy in &mut ctx.map.enemies {
            enemy.kill();
        }
    }

    let already_recorded = unsafe { core::ptr::read_volatile(&raw const VOLCANO_RECORDED) };
    if matches!(solved, VOLCANO_STAGE_FILED) && !already_recorded {
        unsafe {
            core::ptr::write_volatile(&raw mut VOLCANO_RECORDED, true);
        }
        ctx.portal.mark_challenge_solved(challenge_id(MapType::Volcano));
        ctx.recompute_captured_flags();
    }
}

