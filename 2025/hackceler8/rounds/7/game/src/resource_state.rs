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

use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

use megahx8::*;

use crate::res::maps::WorldType;
use crate::res::tileset;
/// Represents the status of an individual tileset.
#[derive(Clone)]
struct Usage {
    tiles: &'static [Tile],
    /// Index into VRAM where this tileset is loaded
    start_index: u16,
    evictable: bool,
}

/// Keeps track of the loaded tiles and their offsets.
///
/// It has a basic logic to keep certain tiles always loaded, they have to be loaded
/// first on game startup.
pub struct State {
    // List of all tiles that can be in use.
    tiles: [Usage; tileset::NUM_ENTRIES],
    pub next_tile_pos: u16,

    /// First position that is evictable - everything before this will not
    /// be resetted when invoking reset().
    first_evictable_pos: u16,
}

pub fn init(vdp: &mut TargetVdp) -> State {
    crate::res::palettes::load_world_palette(WorldType::Overworld, vdp);

    let mut tiles = [const { MaybeUninit::<Usage>::zeroed() }; tileset::NUM_ENTRIES];
    for idx in 0..tileset::NUM_ENTRIES {
        unsafe {
            addr_of_mut!((*tiles[idx].as_mut_ptr()).tiles).write(&tileset::TILESETS[idx]);
            addr_of_mut!((*tiles[idx].as_mut_ptr()).start_index).write(0);
            addr_of_mut!((*tiles[idx].as_mut_ptr()).evictable).write(false);
        }
    }
    State {
        tiles: unsafe { core::mem::transmute(tiles) },
        next_tile_pos: 1,
        first_evictable_pos: 1,
    }
}

impl State {
    pub fn load_tiles_to_vram(
        &mut self,
        vdp: &mut TargetVdp,
        tiles_idx: usize,
        keep_loaded: bool,
    ) -> u16 {
        let usage = &mut self.tiles[tiles_idx];
        if usage.start_index > 0 {
            // Already loaded.
            // Make sure we do not try to load something that was previously loaded as evictable.
            assert!(!(keep_loaded && usage.evictable));
            return usage.start_index;
        }

        if keep_loaded && self.next_tile_pos != self.first_evictable_pos {
            panic!("keep_loaded set but evictable tiles were already loaded");
        }

        usage.start_index = self.next_tile_pos;
        vdp.set_tiles(self.next_tile_pos, usage.tiles);

        #[expect(clippy::cast_possible_truncation)]
        {
            assert!(usage.tiles.len() < u16::MAX.into(), "Too many tiles!");

            self.next_tile_pos += usage.tiles.len() as u16;
            if keep_loaded {
                self.first_evictable_pos += usage.tiles.len() as u16;
            }
            usage.evictable = !keep_loaded;
        }

        usage.start_index
    }

    pub fn reset(&mut self) {
        for t in &mut self.tiles {
            if t.evictable {
                t.start_index = 0;
            }
        }
        self.next_tile_pos = self.first_evictable_pos;
    }

    pub fn clear_screen(vdp: &mut TargetVdp, planes: &[Plane]) {
        for plane in planes {
            vdp.set_plane_tiles(*plane, 0, &[TileFlags::for_tile(0, Palette::A); 64 * 64]);
        }
    }
}
