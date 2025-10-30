// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::map_data;
use crate::spike::Spike;
use crate::tiles;
use crate::wasp::Wasp;
use heapless::Vec;
use megarust::*;

pub struct Map {
    pub scroll_x: i16,
    pub scroll_y: i16,
}

impl Map {
    pub fn new() -> Map {
        Map {
            scroll_x: 0,
            scroll_y: 0,
        }
    }

    pub fn load_bg(&self, vdp: &mut TargetVdp) {
        // #[expect(clippy::cast_possible_truncation)]
        for y in 0..28 {
            let tiles_a = &mut [TileFlags::new(); 40];
            let tiles_b = &mut [TileFlags::new(); 40];
            for x in 0..40 {
                let tile_index_a = map_data::LAYER_A[x + y * map_data::W];
                if tile_index_a != 0 {
                    tiles_a[x] =
                        TileFlags::for_tile(tiles::MAP_TILE_OFFSET + tile_index_a - 1, Palette::D);
                }
                let tile_index_b = map_data::LAYER_B[x + y * map_data::W];
                if tile_index_b != 0 {
                    tiles_b[x] =
                        TileFlags::for_tile(tiles::MAP_TILE_OFFSET + tile_index_b - 1, Palette::D);
                }
            }
            vdp.set_plane_tiles(Plane::A, y as u16 * 64 as u16, tiles_a.as_slice());
            vdp.set_plane_tiles(Plane::B, y as u16 * 64 as u16, tiles_b.as_slice());
        }
    }

    pub fn scroll_bg_x(&mut self, vdp: &mut TargetVdp, dx: i16) -> i16 {
        let prev_scroll_x = self.scroll_x;
        let base = if dx > 0 { 7 } else { 0 };
        let prev_tile_start = (base - self.scroll_x) / 8;
        self.scroll_x = (self.scroll_x - dx)
            .max(map_data::W as i16 * -8 + 320)
            .min(0);
        let new_tile_start = (base - self.scroll_x) / 8;
        let d_cols = (new_tile_start - prev_tile_start).abs();
        let y_tile_start = -self.scroll_y / 8;
        for x in 0..d_cols {
            let map_x = if dx > 0 {
                (39 - x + new_tile_start) as usize
            } else {
                (x + new_tile_start) as usize
            };
            let vdp_x = (map_x % 64) as u16;
            for y in 0..29 {
                let map_y = y + y_tile_start as usize;
                let vdp_y = (map_y % 32) as u16;
                let tiles_a = &mut [TileFlags::new()];
                let tiles_b = &mut [TileFlags::new()];
                let map_index = map_x + map_y * map_data::W;
                if map_index >= map_data::LAYER_A.len() {
                    continue;
                }
                let tile_index_a = map_data::LAYER_A[map_index];
                let tile_index_b = map_data::LAYER_B[map_index];
                if tile_index_a != 0 {
                    tiles_a[0] =
                        TileFlags::for_tile(tiles::MAP_TILE_OFFSET + tile_index_a - 1, Palette::D);
                }
                if tile_index_b != 0 {
                    tiles_b[0] =
                        TileFlags::for_tile(tiles::MAP_TILE_OFFSET + tile_index_b - 1, Palette::D);
                }
                vdp.set_plane_tiles(Plane::A, (vdp_x + vdp_y * 64) as u16, tiles_a.as_slice());
                vdp.set_plane_tiles(Plane::B, (vdp_x + vdp_y * 64) as u16, tiles_b.as_slice());
            }
        }
        vdp.set_h_scroll(0, &[self.scroll_x, self.scroll_x]);
        return prev_scroll_x - self.scroll_x;
    }

    pub fn scroll_bg_y(&mut self, vdp: &mut TargetVdp, dy: i16) -> i16 {
        let prev_scroll_y = self.scroll_y;
        let base = if dy > 0 { 7 } else { 0 };
        let prev_tile_start = (base - self.scroll_y) / 8;
        self.scroll_y = (self.scroll_y - dy)
            .max(map_data::H as i16 * -8 + 224)
            .min(0);
        let new_tile_start = (base - self.scroll_y) / 8;
        let d_rows = (new_tile_start - prev_tile_start).abs();
        let x_tile_start = -self.scroll_x / 8;
        for y in 0..d_rows {
            let map_y = if dy > 0 {
                (27 - y + new_tile_start) as usize
            } else {
                (y + new_tile_start) as usize
            };
            let vdp_y = (map_y % 32) as u16;
            for x in 0..41 {
                let map_x = x + x_tile_start as usize;
                let vdp_x = (map_x % 64) as u16;
                let tiles_a = &mut [TileFlags::new()];
                let tiles_b = &mut [TileFlags::new()];
                let map_index = map_x + map_y * map_data::W;
                if map_index >= map_data::LAYER_A.len() {
                    continue;
                }
                let tile_index_a = map_data::LAYER_A[map_index];
                let tile_index_b = map_data::LAYER_B[map_index];
                if tile_index_a != 0 {
                    tiles_a[0] =
                        TileFlags::for_tile(tiles::MAP_TILE_OFFSET + tile_index_a - 1, Palette::D);
                }
                if tile_index_b != 0 {
                    tiles_b[0] =
                        TileFlags::for_tile(tiles::MAP_TILE_OFFSET + tile_index_b - 1, Palette::D);
                }
                vdp.set_plane_tiles(Plane::A, (vdp_x + vdp_y * 64) as u16, tiles_a.as_slice());
                vdp.set_plane_tiles(Plane::B, (vdp_x + vdp_y * 64) as u16, tiles_b.as_slice());
            }
        }
        vdp.set_v_scroll(0, &[-self.scroll_y, -self.scroll_y]);
        return prev_scroll_y - self.scroll_y;
    }

    pub fn add_new_wasps(&self, dx: i16, dy: i16, wasps: &mut Vec<Wasp, 256>) {
        for (x, y) in map_data::WASPS {
            let x = *x + self.scroll_x + 128;
            let y = *y + self.scroll_y + 128;
            if Wasp::off_screen(x + dx, y + dy) && Wasp::on_screen(x, y) {
                wasps
                    .push(Wasp::new(x as u16, y as u16))
                    .map_err(|_| "too many waspy bois :C")
                    .unwrap();
            }
        }
    }

    // Generics are hard, let's do code duplication
    pub fn add_new_spikes(&self, dx: i16, dy: i16, spikes: &mut Vec<Spike, 64>) {
        for (x, y) in map_data::SPIKES {
            let x = *x + self.scroll_x + 128;
            let y = *y + self.scroll_y + 128;
            if Spike::off_screen(x + dx, y + dy) && Spike::on_screen(x, y) {
                spikes
                    .push(Spike::new(x as u16, y as u16))
                    .map_err(|_| "too many spikes")
                    .unwrap();
            }
        }
    }
}
