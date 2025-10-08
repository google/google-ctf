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

use crate::resource_state::State;

/// The starting vertical scroll of the image UI display plane.
/// Set so the UI is drawn on the bottom part of the plane buffer.
pub const SCREEN_V_SCROLL_TILES: u16 = 36;
pub const SCREEN_V_SCROLL: i16 = 36 * 8;

pub struct Image {
    pub start_tile: u16,
    pub tiles_idx: usize,
    width: u16,
    height: u16,
    pub palette: Palette,
}

impl Image {
    pub fn new(
        res_state: &mut State,
        vdp: &mut TargetVdp,
        tiles_idx: usize,
        width: u16,
        height: u16,
        palette: Palette,
        keep_loaded: bool,
    ) -> Image {
        Image {
            start_tile: res_state.load_tiles_to_vram(vdp, tiles_idx, keep_loaded),
            tiles_idx,
            width,
            height,
            palette,
        }
    }

    /// Draw the image starting from the specified tile coordinates.
    pub fn draw(image: &Image, x: u16, y: u16, vdp: &mut TargetVdp) {
        for image_y in 0..image.height {
            for image_x in 0..image.width {
                let tile_index = image_x + image_y * image.width;
                Self::draw_tile(image, tile_index, x + image_x, y + image_y, vdp);
            }
        }
    }

    /// Clear the image that was previously drawn at the specified tile coordinates.
    pub fn clear(image: &Image, x: u16, y: u16, vdp: &mut TargetVdp) {
        for image_y in 0..image.height {
            for image_x in 0..image.width {
                Self::clear_tile(x + image_x, y + image_y, vdp);
            }
        }
    }

    /// Draw a specific tile of an image at the specified tile coordinates.
    pub fn draw_tile(image: &Image, tile_index: u16, x: u16, y: u16, vdp: &mut TargetVdp) {
        let tiles = &mut [TileFlags::new()];
        tiles[0] =
            *TileFlags::for_tile(image.start_tile + tile_index, image.palette).set_priority(true);
        vdp.set_plane_tiles(Plane::B, (y + SCREEN_V_SCROLL_TILES) * 64 + x, tiles);
    }

    /// Clear an image tile at the specified tile coordinates.
    pub fn clear_tile(x: u16, y: u16, vdp: &mut TargetVdp) {
        vdp.set_plane_tiles(
            Plane::B,
            (y + SCREEN_V_SCROLL_TILES) * 64 + x,
            &[*TileFlags::new().set_priority(true)],
        );
    }
}
