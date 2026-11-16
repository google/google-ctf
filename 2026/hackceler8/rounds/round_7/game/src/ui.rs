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

use heapless::String;
use megahx8::*;

use crate::image::Image;
use crate::map::Map;
use crate::res::images;
use crate::resource_state::State;
use crate::Player;

// Location of the given ASCII char in the tile image. '?' is used as the placeholder for unprintable chars.
pub(crate) const CHAR_TILES_INDICES: &[u8] = &[
    82, 82, 82, 82, 82, 82, 82, 82, 82, 95, 96, 98, 99, 97, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
    82, 82, 82, 82, 82, 82, 82, 82, 94, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 77, 78, 79, 80, 81, 82, 83, 36, 37, 38, 39, 40, 41, 42, 43, 44,
    45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 84, 85, 86, 87, 88, 89, 10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
    35, 90, 91, 92, 93, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
    82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
    82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
    82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
    82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
    82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82, 82,
];

// The location of health bars.
const PLAYER_HEALTH_BAR_X: u16 = 1;
const PLAYER_HEALTH_BAR_Y: u16 = 11;
const BOSS_HEALTH_BAR_X: u16 = 38;
const BOSS_HEALTH_BAR_Y: u16 = 21;

pub struct UI {
    pub text_img: Image,
    health_img: Image,
    health_empty_img: Image,
    health_bottom_img: Image,
    flag_img: Image,
    pub choice_arrow_img: Image,
    pub text_arrow_img: Image,
    pub inventory_text_img: Image,
    pub inventory_border_img: Image,
    render_state: RenderState,
}

struct RenderState {
    first_render_done: bool,
    // Previous recorded health of the player. None if the player
    // was previously not active.
    last_health: Option<u16>,
    // Previous recorded health of the boss. None if the boss
    // was previously not on the map.
    last_boss_health: Option<u16>,
    last_captured_flags: u16,
    last_frame: u32,
}

impl RenderState {
    fn new() -> RenderState {
        Self {
            first_render_done: false,
            last_health: None,
            last_boss_health: None,
            last_captured_flags: 0,
            last_frame: u32::MAX,
        }
    }
}

impl UI {
    pub fn new(res_state: &mut State, vdp: &mut TargetVdp) -> Self {
        UI {
            text_img: images::text::new(res_state, vdp, /* keep_loaded= */ true),
            health_img: images::health::new(res_state, vdp, /* keep_loaded= */ true),
            health_empty_img: images::health_empty::new(
                res_state, vdp, /* keep_loaded= */ true,
            ),
            health_bottom_img: images::health_bottom::new(
                res_state, vdp, /* keep_loaded= */ true,
            ),
            flag_img: images::flag::new(res_state, vdp, /* keep_loaded= */ true),
            choice_arrow_img: images::choice_arrow::new(
                res_state, vdp, /* keep_loaded= */ true,
            ),
            text_arrow_img: images::text_arrow::new(res_state, vdp, /* keep_loaded= */ true),
            inventory_text_img: images::inventory_text::new(
                res_state, vdp, /* keep_loaded= */ true,
            ),
            inventory_border_img: images::inventory_border::new(
                res_state, vdp, /* keep_loaded= */ true,
            ),
            render_state: RenderState::new(),
        }
    }

    /// Preload all sprites that must always be loaded.
    pub fn preload_persistent_sprites(res_state: &mut State, vdp: &mut TargetVdp) {
        images::text::new(res_state, vdp, /* keep_loaded= */ true);
        images::health::new(res_state, vdp, /* keep_loaded= */ true);
        images::health_empty::new(res_state, vdp, /* keep_loaded= */ true);
        images::health_bottom::new(res_state, vdp, /* keep_loaded= */ true);
        images::flag::new(res_state, vdp, /* keep_loaded= */ true);
        images::choice_arrow::new(res_state, vdp, /* keep_loaded= */ true);
        images::text_arrow::new(res_state, vdp, /* keep_loaded= */ true);
        images::inventory_text::new(res_state, vdp, /* keep_loaded= */ true);
        images::inventory_border::new(res_state, vdp, /* keep_loaded= */ true);
    }

    pub fn clear(&mut self) {
        self.render_state = RenderState::new();
    }

    pub fn render(
        &mut self,
        player: &Player,
        map: &Map,
        captured_flags: u16,
        frame: u32,
        vdp: &mut TargetVdp,
    ) {
        if !self.render_state.first_render_done {
            // Clear any previous inventory renders.
            State::clear_screen(vdp, &[Plane::B]);
        }
        self.render_health(player, vdp);
        self.render_boss_health(map, vdp);
        self.render_flags(captured_flags, vdp);
        self.render_cycles(frame, vdp);
        self.render_hr_hud(map, vdp);
        self.render_state.first_render_done = true;
    }

    fn render_health(&mut self, player: &Player, vdp: &mut TargetVdp) {
        if !player.is_active() {
            return;
        }

        if !self.render_state.first_render_done {
            Image::draw(
                &self.health_bottom_img,
                PLAYER_HEALTH_BAR_X,
                PLAYER_HEALTH_BAR_Y + 1,
                vdp,
                Plane::B,
            );
        }

        let mut last_health = 0;
        if let Some(h) = self.render_state.last_health {
            last_health = h;
        }

        if player.health < last_health {
            for i in player.health..last_health {
                Image::draw(
                    &self.health_empty_img,
                    PLAYER_HEALTH_BAR_X,
                    PLAYER_HEALTH_BAR_Y - i,
                    vdp,
                    Plane::B,
                );
            }
        } else if player.health > last_health {
            for i in last_health..player.health {
                Image::draw(
                    &self.health_img,
                    PLAYER_HEALTH_BAR_X,
                    PLAYER_HEALTH_BAR_Y - i,
                    vdp,
                    Plane::B,
                );
            }
        }
        self.render_state.last_health = Some(player.health);
    }

    fn render_boss_health(&mut self, map: &Map, vdp: &mut TargetVdp) {
        let health = map
            .enemies
            .iter()
            .find(|enemy| enemy.is_boss() && !enemy.invulnerable)
            .map(|enemy| enemy.health());

        let last_health = self.render_state.last_boss_health.unwrap_or({
            if health.is_none() {
                // Boss still not active, nothing to do.
                return;
            } else {
                0
            }
        });
        self.render_state.last_boss_health = health;

        let health = health.unwrap_or(0);
        if health < last_health {
            for i in health..last_health {
                Image::draw(
                    &self.health_empty_img,
                    BOSS_HEALTH_BAR_X,
                    BOSS_HEALTH_BAR_Y - i,
                    vdp,
                    Plane::B,
                );
            }
        } else if health > last_health {
            for i in last_health..health {
                Image::draw(
                    &self.health_img,
                    BOSS_HEALTH_BAR_X,
                    BOSS_HEALTH_BAR_Y - i,
                    vdp,
                    Plane::B,
                );
            }
        }
    }

    fn render_flags(&mut self, captured_flags: u16, vdp: &mut TargetVdp) {
        if !self.render_state.first_render_done {
            Image::draw(&self.flag_img, 34, 0, vdp, Plane::B);
            Self::draw_text(":0", 36, 1, &self.text_img, vdp, Plane::B); // Start with 0 flags.
        }
        if self.render_state.last_captured_flags != captured_flags {
            let mut amount_str: String<5> = String::new();
            let _ = write!(amount_str, "{}", captured_flags);
            Self::draw_text(&amount_str, 37, 1, &self.text_img, vdp, Plane::B);
            self.render_state.last_captured_flags = captured_flags;
        }
    }

    fn render_cycles(&mut self, frame: u32, vdp: &mut TargetVdp) {
        if !self.render_state.first_render_done || self.render_state.last_frame != frame {
            let mut amount_str: String<16> = String::new();
            let _ = write!(amount_str, "C: {}", frame);
            Self::draw_text(&amount_str, 24, 1, &self.text_img, vdp, Plane::B);
            self.render_state.last_frame = frame;
        }
    }

    /// Draw the specified text starting from the specified tile coordinates.
    pub fn draw_text(
        text: &str,
        x: u16,
        y: u16,
        text_img: &Image,
        vdp: &mut TargetVdp,
        plane: Plane,
    ) {
        for (i, chr) in text.as_bytes().iter().enumerate() {
            Self::draw_text_char(*chr, x + i as u16, y, text_img, vdp, plane);
        }
    }

    /// Clear text that has previously been drawn with draw_text.
    pub fn clear_text(text: &str, x: u16, y: u16, vdp: &mut TargetVdp, plane: Plane) {
        for i in 0..text.len() {
            Image::clear_tile(x + i as u16, y, vdp, plane);
        }
    }

    pub fn draw_text_char(
        chr: u8,
        x: u16,
        y: u16,
        text_img: &Image,
        vdp: &mut TargetVdp,
        plane: Plane,
    ) {
        Image::draw_tile(
            text_img,
            CHAR_TILES_INDICES[chr as usize] as u16,
            x,
            y,
            vdp,
            plane,
        );
    }
}

const HUD_SLOT_WIDTH: usize = 18;
const HUD_PLANE_STRIDE: u16 = 64;
const HUD_COL_X: u16 = 3;
const HUD_LINE1_Y: u16 = 1;
const HUD_LINE2_Y: u16 = 2;
const VOLCANO_HUD_TAG: u32 = 0x2000_0000;
const VOLCANO_DOCKED_SHIFT: u32 = 26;
const VOLCANO_SOLVED_SHIFT: u32 = 24;
const VOLCANO_ALTAR_SHIFT: u32 = 23;
const VOLCANO_BUFLEN_SHIFT: u32 = 16;
const VOLCANO_PACKET_CAP: u16 = 6;
const VOLCANO_DOCKED_OVERTIME: u16 = 2;
const VOLCANO_STAGE_APPROVED: u16 = 1;
const VOLCANO_STAGE_FILED: u16 = 2;
const VOLCANO_CHORD_MASK: u16 = 0x7F;

impl UI {
    #[inline(never)]
    fn draw_hud_slot(&self, text: &str, x: u16, y: u16, width: usize, vdp: &mut TargetVdp) {
        let bytes = text.as_bytes();
        let mut row = [TileFlags::new(); HUD_SLOT_WIDTH];
        let n = width.min(row.len());
        for i in 0..n {
            if i < bytes.len() && !matches!(bytes[i], b' ') {
                let tile_idx = CHAR_TILES_INDICES[bytes[i] as usize] as u16;
                row[i] = *TileFlags::for_tile(
                    self.text_img.start_tile + tile_idx,
                    self.text_img.palette,
                )
                .set_priority(true);
            } else {
                row[i] = *TileFlags::new().set_priority(true);
            }
        }
        vdp.set_plane_tiles(Plane::B, y * HUD_PLANE_STRIDE + x, &row[..n]);
    }

    fn render_hr_hud(&mut self, map: &Map, vdp: &mut TargetVdp) {
        use crate::res::maps::MapType;
        if matches!(map.map_type, MapType::Volcano) {
            self.render_volcano_dossier_hud(vdp);
        }
    }

    fn render_volcano_dossier_hud(&self, vdp: &mut TargetVdp) {
        let (buf_len, calls, solved, altar, docked, c0, c1, c2, c3, c4) = unsafe {
            (
                core::ptr::read_volatile(&raw const crate::hr_volcano::VOLCANO_STATE.buf_len),
                core::ptr::read_volatile(&raw const crate::hr_volcano::VOLCANO_STATE.calls),
                core::ptr::read_volatile(&raw const crate::hr_volcano::VOLCANO_STATE.solved),
                core::ptr::read_volatile(&raw const crate::hr_volcano::VOLCANO_STATE.altar),
                core::ptr::read_volatile(&raw const crate::hr_volcano::VOLCANO_STATE.docked),
                core::ptr::read_volatile(&raw const crate::hr_volcano::VOLCANO_STATE.chord_buf[0]),
                core::ptr::read_volatile(&raw const crate::hr_volcano::VOLCANO_STATE.chord_buf[1]),
                core::ptr::read_volatile(&raw const crate::hr_volcano::VOLCANO_STATE.chord_buf[2]),
                core::ptr::read_volatile(&raw const crate::hr_volcano::VOLCANO_STATE.chord_buf[3]),
                core::ptr::read_volatile(&raw const crate::hr_volcano::VOLCANO_STATE.chord_buf[4]),
            )
        };
        let chord_hash = ((c0 as u32) << 12)
            ^ ((c1 as u32) << 9)
            ^ ((c2 as u32) << 6)
            ^ ((c3 as u32) << 3)
            ^ (c4 as u32);
        let key: u32 = VOLCANO_HUD_TAG
            | ((docked as u32 & 0x03) << VOLCANO_DOCKED_SHIFT)
            | ((solved as u32 & 0x03) << VOLCANO_SOLVED_SHIFT)
            | ((altar as u32 & 1) << VOLCANO_ALTAR_SHIFT)
            | ((buf_len as u32 & 0x0F) << VOLCANO_BUFLEN_SHIFT)
            | ((calls as u32 ^ chord_hash) & 0xFFFF);
        let prev_key = unsafe { core::ptr::read_volatile(&raw const crate::hr_volcano::HR_HUD_CACHE) };
        if matches!(key ^ prev_key, 0) {
            return;
        }
        unsafe {
            core::ptr::write_volatile(&raw mut crate::hr_volcano::HR_HUD_CACHE, key);
        }

        let bar = match buf_len {
            0 => "......",
            1 => "#.....",
            2 => "##....",
            3 => "###...",
            4 => "####..",
            5 => "#####.",
            _ => "######",
        };
        let mut line1: String<HUD_SLOT_WIDTH> = String::new();
        let mut line2: String<HUD_SLOT_WIDTH> = String::new();
        if matches!(solved, VOLCANO_STAGE_FILED) {
            let _ = write!(line1, "HR:[######] PWNED!");
            let _ = write!(line2, "SUMMIT FILED OK!");
        } else if matches!(solved, VOLCANO_STAGE_APPROVED) {
            let _ = write!(line1, "HR:[######] SEALED");
            let _ = write!(line2, "JUMP->SUMMIT X456");
        } else if buf_len > 0 {
            let _ = write!(
                line1,
                "HR:[{}] {}/{}",
                bar,
                buf_len.min(VOLCANO_PACKET_CAP),
                VOLCANO_PACKET_CAP
            );
            let _ = write!(line2, "IN:");
            let slots = [c0, c1, c2, c3, c4];
            for (idx, &val) in slots.iter().enumerate() {
                if idx > 0 {
                    let _ = line2.push('.');
                }
                if (idx as u16) < buf_len {
                    let _ = write!(line2, "{:02X}", val & VOLCANO_CHORD_MASK);
                } else {
                    let _ = line2.push_str("--");
                }
            }
        } else if matches!(docked, VOLCANO_DOCKED_OVERTIME) {
            let _ = write!(line1, "HR:DOCKED >C!");
            let _ = write!(line2, "TENURE HOLD=1!");
        } else if !matches!(docked, 0) {
            let _ = write!(line1, "HR:AUDIT FAIL!");
            let _ = write!(line2, "RUBRIC REJECT!");
        } else if !matches!(altar, 0) {
            let _ = write!(line1, "HR:[......] READY!");
            let _ = write!(line2, "IN:--.--.--.--.--");
        } else {
            let _ = write!(line1, "HR:[......] 0/6");
            let _ = write!(line2, "STEP RIGHT X>=320");
        }
        self.draw_hud_slot(&line1, HUD_COL_X, HUD_LINE1_Y, HUD_SLOT_WIDTH, vdp);
        self.draw_hud_slot(&line2, HUD_COL_X, HUD_LINE2_Y, HUD_SLOT_WIDTH, vdp);
    }
}

