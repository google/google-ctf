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

use heapless::String;
use megahx8::*;

use crate::fader;
use crate::game;
use crate::image::Image;
use crate::res::images;
use crate::res::maps::WorldType;
use crate::resource_state::State;
use crate::world::World;
use crate::Player;

// Location of the given ASCII char in the tile image. '?' is used as the placeholder for unprintable chars.
pub const CHAR_TILES_INDEXES: &[u8] = &[
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

// The dimensions of the item buttons' border, in tiles.
const INVENTORY_BORDER_W_TILES: u16 = 15;
const INVENTORY_BORDER_H_TILES: u16 = 3;

// The location of the boss's health bar.
const BOSS_HEALTH_BAR_X: u16 = 10;
const BOSS_HEALTH_BAR_Y: u16 = 0;

pub struct UI {
    text_img: Image,
    heart_img: Image,
    health_bar_img: Image,
    flag_img: Image,
    pub choice_arrow_img: Image,
    pub text_arrow_img: Image,
    pub inventory_text_img: Image,
    pub inventory_border_img: Image,
    inventory_border_selected_img: Image,
    render_state: RenderState,
}

struct RenderState {
    first_render_done: bool,
    // Previous recorded health of players. None if the player
    // was previously not active.
    last_health: [Option<u16>; game::MAX_PLAYERS],
    // Previous recorded health of the boss. None if the boss
    // was previously not on the map.
    last_boss_health: Option<u16>,
    last_captured_flags: u16,
    inventory_needs_update: bool,
    world_type: WorldType,
}

impl RenderState {
    fn new(world_type: WorldType) -> RenderState {
        Self {
            first_render_done: false,
            last_health: [None; game::MAX_PLAYERS],
            last_boss_health: None,
            last_captured_flags: 0,
            inventory_needs_update: false,
            world_type,
        }
    }
}

impl UI {
    pub fn new(res_state: &mut State, vdp: &mut TargetVdp, world_type: WorldType) -> Self {
        UI {
            text_img: images::text::new(res_state, vdp, /* keep_loaded= */ true),
            heart_img: images::heart::new(res_state, vdp, /* keep_loaded= */ true),
            health_bar_img: images::health_bar::new(res_state, vdp, /* keep_loaded= */ true),
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
            inventory_border_selected_img: images::inventory_border_selected::new(
                res_state, vdp, /* keep_loaded= */ true,
            ),
            render_state: RenderState::new(world_type),
        }
    }

    /// Preload all sprites that must always be loaded.
    pub fn preload_persistent_sprites(res_state: &mut State, vdp: &mut TargetVdp) {
        images::text::new(res_state, vdp, /* keep_loaded= */ true);
        images::heart::new(res_state, vdp, /* keep_loaded= */ true);
        images::health_bar::new(res_state, vdp, /* keep_loaded= */ true);
        images::flag::new(res_state, vdp, /* keep_loaded= */ true);
        images::choice_arrow::new(res_state, vdp, /* keep_loaded= */ true);
        images::text_arrow::new(res_state, vdp, /* keep_loaded= */ true);
        images::inventory_text::new(res_state, vdp, /* keep_loaded= */ true);
        images::inventory_border::new(res_state, vdp, /* keep_loaded= */ true);
        images::inventory_border_selected::new(res_state, vdp, /* keep_loaded= */ true);
    }

    pub fn clear(&mut self, world: &World) {
        self.render_state = RenderState::new(world.world_type);
    }

    pub fn render(
        &mut self,
        players: &[Player],
        world: &World,
        captured_flags: u16,
        vdp: &mut TargetVdp,
    ) {
        if !self.render_state.first_render_done {
            // Clear any previous inventory renders.
            State::clear_screen(vdp, &[Plane::B]);
        }
        self.render_hearts(players, vdp);
        self.render_boss_health(world, vdp);
        self.render_flags(captured_flags, vdp);
        self.render_or_clear_inventory_tiles(world, vdp);
        self.render_state.first_render_done = true;
    }

    fn render_hearts(&mut self, players: &[Player], vdp: &mut TargetVdp) {
        for p in 0..players.len() {
            let player = &players[p];
            let x = (p / 2) as u16 * 18;
            let y = (p % 2) as u16 * 2
                + if matches!(self.render_state.world_type, WorldType::BossTemple) {
                    23
                } else {
                    0
                };

            if !self.render_state.first_render_done {
                let mut player_name: String<16> = String::new();
                let _ = write!(player_name, "P{}: Press START", p + 1);
                Self::draw_text(&player_name, x, y + 1, &self.text_img, vdp);
            }

            if !player.active {
                continue;
            }

            let mut last_health = 0;
            if let Some(h) = self.render_state.last_health[p] {
                last_health = h;
            } else {
                // Player recently became active.
                Self::clear_text("Press START", x + 4, y + 1, vdp);
            }

            if player.health < last_health {
                for i in player.health..last_health {
                    Image::clear(&self.heart_img, x + 3 + i * 2, y, vdp);
                }
            } else if player.health > last_health {
                for i in last_health..player.health {
                    Image::draw(&self.heart_img, x + 3 + i * 2, y, vdp);
                }
            }
            self.render_state.last_health[p] = Some(player.health);
        }
    }

    fn render_boss_health(&mut self, world: &World, vdp: &mut TargetVdp) {
        let health = world
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
                Image::clear_tile(BOSS_HEALTH_BAR_X + 1 + i, BOSS_HEALTH_BAR_Y, vdp);
            }
        } else if health > last_health {
            for i in last_health..health {
                Image::draw_tile(
                    &self.health_bar_img,
                    /*tile_num=*/ 1,
                    BOSS_HEALTH_BAR_X + 1 + i,
                    BOSS_HEALTH_BAR_Y,
                    vdp,
                );
            }
        }
        // Also update the starting and ending tiles of the health bar.
        if health != last_health {
            if health == 0 {
                Image::clear_tile(BOSS_HEALTH_BAR_X, BOSS_HEALTH_BAR_Y, vdp);
                Image::clear_tile(BOSS_HEALTH_BAR_X + 1, BOSS_HEALTH_BAR_Y, vdp);
            } else {
                Image::draw_tile(
                    &self.health_bar_img,
                    /*tile_num=*/ 0,
                    BOSS_HEALTH_BAR_X,
                    BOSS_HEALTH_BAR_Y,
                    vdp,
                );
                Image::draw_tile(
                    &self.health_bar_img,
                    /*tile_num=*/ 2,
                    BOSS_HEALTH_BAR_X + health,
                    BOSS_HEALTH_BAR_Y,
                    vdp,
                );
            }
        }
    }

    fn render_flags(&mut self, captured_flags: u16, vdp: &mut TargetVdp) {
        if !self.render_state.first_render_done {
            Image::draw(&self.flag_img, 34, 0, vdp);
            Self::draw_text(":0", 36, 1, &self.text_img, vdp); // Start with 0 flags.
        }
        if self.render_state.last_captured_flags != captured_flags {
            let mut amount_str: String<5> = String::new();
            let _ = write!(amount_str, "{}", captured_flags);
            Self::draw_text(&amount_str, 37, 1, &self.text_img, vdp);
            self.render_state.last_captured_flags = captured_flags;
        }
    }

    fn render_or_clear_inventory_tiles(&mut self, world: &World, vdp: &mut TargetVdp) {
        if !self.render_state.inventory_needs_update {
            return;
        }
        self.render_state.inventory_needs_update = false;

        let item_x = 40 / 2 - INVENTORY_BORDER_W_TILES / 2;
        let item_start_y =
            28 / 2 - (INVENTORY_BORDER_H_TILES + 1) * (world.inventory.items.len() as u16) / 2;
        let text_x = item_x + 1;
        let text_y = item_start_y + 1;

        if world.inventory.items.is_empty() {
            let txt = " * No items * ";
            if world.inventory.scene.is_none() {
                for x in 0..txt.len() as u16 {
                    Image::clear_tile(text_x + x, text_y, vdp);
                }
            } else {
                Self::draw_text(txt, text_x, text_y, &self.inventory_text_img, vdp);
            }
        }

        for (i, item) in world.inventory.items.iter().enumerate() {
            let item_y = item_start_y + (i as u16) * (INVENTORY_BORDER_H_TILES + 1);

            // Draw border
            for tile_y in 0..3 {
                for tile_x in 0..INVENTORY_BORDER_W_TILES + 1 {
                    if let Some(scene) = &world.inventory.scene {
                        // Different image if this item is selected
                        let mut border_img = &self.inventory_border_img;
                        if let Some(selection) = scene.selection {
                            if selection == i {
                                border_img = &self.inventory_border_selected_img;
                            }
                        }

                        // Select correct border side
                        let tile_num = match (tile_x, tile_y) {
                            // Edges
                            (0, 0) => 0,
                            (0, 2) => 6,
                            (INVENTORY_BORDER_W_TILES, 0) => 2,
                            (INVENTORY_BORDER_W_TILES, 2) => 8,
                            // Faces
                            (0, _) => 3,
                            (INVENTORY_BORDER_W_TILES, _) => 5,
                            (_, 0) => 1,
                            (_, 2) => 7,
                            // Middle
                            _ => 4,
                        };
                        Image::draw_tile(
                            border_img,
                            tile_num,
                            item_x + tile_x,
                            item_y + tile_y,
                            vdp,
                        );
                    } else {
                        Image::clear_tile(item_x + tile_x, item_y + tile_y, vdp);
                    }
                }
            }

            if world.inventory.scene.is_none() {
                // Everything cleared, nothing left to do
                continue;
            }

            // Draw item text
            let text_y = item_y + 1;
            let name = item.display_name();
            Self::draw_text(name, text_x, text_y, &self.inventory_text_img, vdp);
            if item.amount != 1 {
                let mut amount_str: String<5> = String::new();
                let _ = write!(amount_str, "x{}", item.amount);
                Self::draw_text(
                    &amount_str,
                    text_x + name.len() as u16 + 1,
                    text_y,
                    &self.inventory_text_img,
                    vdp,
                );
            }
            if let Some(worn_by) = item.worn_by {
                let mut player_str: String<7> = String::new();
                let _ = write!(player_str, "(P{})", worn_by + 1);
                Self::draw_text(
                    &player_str,
                    text_x + name.len() as u16 + 1,
                    text_y,
                    &self.inventory_text_img,
                    vdp,
                );
            }
        }

        // Add/remove semi-transparent dark background
        let fade_amount = if world.inventory.scene.is_none() {
            32
        } else {
            16
        };
        fader::fade_palettes(
            fader::FadeColor::Black,
            self.render_state.world_type,
            // Palette::B (inventory palette) should not be darkened
            &[Palette::A, Palette::C, Palette::D],
            fade_amount,
            vdp,
        );
    }

    /// Refresh the inventory display on the next render call.
    pub fn mark_inventory_for_refresh(&mut self) {
        self.render_state.inventory_needs_update = true;
    }

    /// Draw the specified text starting from the specified tile coordinates.
    pub fn draw_text(text: &str, x: u16, y: u16, text_img: &Image, vdp: &mut TargetVdp) {
        for (i, chr) in text.as_bytes().iter().enumerate() {
            Self::draw_text_char(*chr, x + i as u16, y, text_img, vdp);
        }
    }

    /// Clear text that has previously been drawn with draw_text.
    pub fn clear_text(text: &str, x: u16, y: u16, vdp: &mut TargetVdp) {
        for i in 0..text.len() {
            Image::clear_tile(x + i as u16, y, vdp);
        }
    }

    pub fn draw_text_char(chr: u8, x: u16, y: u16, text_img: &Image, vdp: &mut TargetVdp) {
        Image::draw_tile(text_img, CHAR_TILES_INDEXES[chr as usize] as u16, x, y, vdp);
    }
}
