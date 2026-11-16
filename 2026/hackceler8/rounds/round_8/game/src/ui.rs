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
