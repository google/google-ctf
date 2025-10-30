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

use crate::map::Map;
use megarust::*;

pub fn get_ground_y(mut ground_x: i16, map: &Map, vdp: &mut TargetVdp) -> u16 {
    ground_x = ground_x.max(0).min(319);
    let (ground_tile_index, ground_tile_y) = find_ground_tile(ground_x, map, vdp);
    if ground_tile_index == 0 {
        return 224;
    }
    let mut ground_y = (ground_tile_y * 8 + map.scroll_y % 8) as u16;
    ground_y += find_first_solid_pixel_y(ground_tile_index, ground_x, map, vdp);
    ground_y
}

fn find_ground_tile(ground_x: i16, map: &Map, vdp: &mut TargetVdp) -> (u16, i16) {
    let map_x = (ground_x - map.scroll_x) / 8;
    let vdp_x = (map_x % 64) as u16;
    let mut tile_y = 41;
    let mut tile_index = 0;
    for y in 0..40 {
        let vdp_y = ((y - map.scroll_y / 8) % 32) as u16;
        let tile = vdp.get_plane_tile(Plane::B, (vdp_x + vdp_y * 64) as u16);
        tile_index = tile.tile_index();
        if tile.tile_index() != 0 {
            tile_y = y;
            break;
        }
    }
    (tile_index, tile_y)
}

fn find_first_solid_pixel_y(tile_index: u16, ground_x: i16, map: &Map, vdp: &mut TargetVdp) -> u16 {
    let tile_data = vdp.get_tile(tile_index);
    let pixel_x = (ground_x - map.scroll_x) % 8;
    for pixel_y in 0..8 {
        // 2 colors stored in 1 byte
        let mut c = tile_data.0[(pixel_x / 2) as usize + pixel_y * 4];
        if pixel_x % 2 == 0 {
            c &= 0xf;
        } else {
            c >>= 4;
        }
        if c != 0 {
            return pixel_y as u16;
        }
    }
    return 8;
}
