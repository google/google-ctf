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
use resources::MapTileAttribute;

use crate::door::DoorProperties;
use crate::enemy::EnemyProperties;
use crate::entity::*;
use crate::image;
use crate::item::ItemProperties;
use crate::npc::NpcProperties;
use crate::res::enemies::EnemyType;
use crate::res::items::ItemType;
use crate::res::npcs::NpcType;
use crate::resource_state::State;
use crate::switch::SwitchProperties;
use crate::PlaneAddress;

// Width of maps in tiles
pub const WIDTH: usize = 40;
// Height of maps in tiles
pub const HEIGHT: usize = 28;

pub type NewFn = fn() -> Map;

/// macro to get the current map from [`Ctx`]
#[macro_export]
macro_rules! get_map {
    ($ctx:ident) => {
        $ctx.world.map.as_ref().unwrap()
    };
}

/// macro to get the current map from [`Ctx`], mut
#[macro_export]
macro_rules! get_map_mut {
    ($ctx:ident) => {
        $ctx.world.map.as_mut().unwrap()
    };
}

pub struct Array2d<'a, T> {
    data: &'a [T],
    width: usize,
    height: usize,
}

impl<'a, T> Array2d<'a, T> {
    pub const fn new(data: &'a [T], width: usize, height: usize) -> Self {
        assert!(data.len() == width * height);
        Self {
            data,
            width,
            height,
        }
    }

    pub fn get(&self, x: usize, y: usize) -> Option<&T> {
        if x < self.width && y < self.height {
            Some(&self.data[x + y * self.width])
        } else {
            None
        }
    }
}

type GfxLayer = Array2d<'static, u16>;
type AttrLayer = Array2d<'static, u8>;

/// Stores which map tiles an entity hit at one point.
#[derive(Copy, Clone)]
pub struct HitTiles {
    /// Tile types that were touched by at least one tile of the entity.
    any_hit_bitmask: MapTileAttribute,
    /// Tile types that were touched by all tiles the entity.
    all_hit_bitmask: MapTileAttribute,
}

impl HitTiles {
    /// Whether the entity touches a tile of the given attribute type.
    pub fn touches_tile(self, tile_type: MapTileAttribute) -> bool {
        self.any_hit_bitmask & tile_type != 0
    }

    /// Whether the entity was immersed in a tile of the given attribute type.
    /// Used to e.g. check if an entity should fall down a hole.
    pub fn immersed_in_tile(self, tile_type: MapTileAttribute) -> bool {
        self.all_hit_bitmask & tile_type != 0
    }
}

pub struct Map {
    start_tile: Option<u16>,
    tiles_idx: usize,
    gfx_layer: GfxLayer,
    attr_layer: AttrLayer,
    palette: Palette,

    // default + 4 cardinal directions
    pub(crate) player_spawn_position: Option<(i16, i16)>,
    pub(crate) enemies: &'static [(EnemyType, u16, i16, i16, &'static EnemyProperties)],
    pub(crate) npcs: &'static [(NpcType, i16, i16, &'static NpcProperties)],
    pub(crate) items: &'static [(ItemType, i16, i16, &'static ItemProperties)],
    pub(crate) doors: &'static [(i16, i16, &'static DoorProperties)],
    pub(crate) switches: &'static [(i16, i16, &'static SwitchProperties)],
}

impl Map {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        tiles_idx: usize,
        gfx_layer: GfxLayer,
        attr_layer: AttrLayer,
        palette: Palette,
        player_spawn_position: Option<(i16, i16)>,
        enemies: &'static [(EnemyType, u16, i16, i16, &EnemyProperties)],
        npcs: &'static [(NpcType, i16, i16, &NpcProperties)],
        items: &'static [(ItemType, i16, i16, &ItemProperties)],
        doors: &'static [(i16, i16, &DoorProperties)],
        switches: &'static [(i16, i16, &SwitchProperties)],
    ) -> Map {
        Map {
            start_tile: None,
            tiles_idx,
            gfx_layer,
            attr_layer,
            palette,
            player_spawn_position,
            enemies,
            npcs,
            items,
            doors,
            switches,
        }
    }

    /// Load the map to vram
    pub(crate) fn load_to_vram(
        &mut self,
        vram_offset: PlaneAddress,
        vdp: &mut TargetVdp,
        res_state: &mut State,
    ) {
        let start_tile = self.init_tiles(vdp, res_state);
        vdp.set_plane_size(ScrollSize::Cell64, ScrollSize::Cell64);
        vdp.set_h_scroll(0, &[-(vram_offset.0 as i16), 0]);
        vdp.set_v_scroll(0, &[vram_offset.1 as i16, image::SCREEN_V_SCROLL]);
        // #[expect(clippy::cast_possible_truncation)]
        for y in 0..self.gfx_layer.height {
            let tiles = &mut [TileFlags::new(); 40];
            for x in 0..self.gfx_layer.width.min(40) {
                let tile_index = self.gfx_layer.get(x, y).unwrap();
                if *tile_index != 0 {
                    tiles[x] = TileFlags::for_tile(start_tile + tile_index - 1, self.palette);
                }
            }

            let addr = vram_offset.to_address();
            vdp.set_plane_tiles(Plane::A, addr + (y * 64) as u16, tiles.as_slice());
        }
    }

    pub(crate) fn load_tile_column(
        &mut self,
        column_index: u16,
        // Describes the vram offset where the column should be inserted into
        vram_offset: PlaneAddress,
        vdp: &mut TargetVdp,
        res_state: &mut State,
    ) {
        if column_index >= 40 {
            // Means that the scrolling logic is buggy.
            panic!("Column index is out of bounds");
        }
        let start_tile = self.init_tiles(vdp, res_state);

        for y in 0..self.gfx_layer.height {
            let mut tile = TileFlags::new();
            let tile_index = self.gfx_layer.get(column_index as usize, y).unwrap();
            if *tile_index != 0 {
                tile = TileFlags::for_tile(start_tile + tile_index - 1, self.palette);
            }

            vdp.set_plane_tiles(
                Plane::A,
                (vram_offset + (0i16, y as i16)).to_address(),
                &[tile],
            );
        }
    }

    pub(crate) fn load_tile_row(
        &mut self,
        row_index: u16,
        // Describes the vram offset where the column should be inserted into
        vram_offset: PlaneAddress,
        vdp: &mut TargetVdp,
        res_state: &mut State,
    ) {
        if row_index >= 28 {
            // Means that the scrolling logic is buggy.
            panic!("Row index is out of bounds");
        }
        let start_tile = self.init_tiles(vdp, res_state);

        for x in 0..self.gfx_layer.width.min(40) {
            let mut tile = TileFlags::new();
            let tile_index = self.gfx_layer.get(x, row_index as usize).unwrap();
            if *tile_index != 0 {
                tile = TileFlags::for_tile(start_tile + tile_index - 1, self.palette);
            }
            vdp.set_plane_tiles(
                Plane::A,
                (vram_offset + (x as i16, 0_i16)).to_address(),
                &[tile],
            );
        }
    }

    /// Load this map tiles into the VRAM if it's not loaded yet.
    /// Return the start index of the loaded tiles.
    fn init_tiles(&mut self, vdp: &mut TargetVdp, res_state: &mut State) -> u16 {
        if self.start_tile.is_none() {
            self.start_tile = Some(res_state.load_tiles_to_vram(
                vdp,
                self.tiles_idx,
                /* keep_loaded= */ false,
            ));
        }
        self.start_tile.unwrap()
    }

    /// Compute and return all the tiles of this map that are hit by the hitbox.
    pub fn get_hit_tiles(&self, hitbox: &Hitbox) -> HitTiles {
        let x = hitbox.x;
        let y = hitbox.y;
        let w = hitbox.w;
        let h = hitbox.h;

        let mut hit_tiles = HitTiles {
            // Start with all bits cleared, add hits in the loop.
            any_hit_bitmask: MapTileAttribute::none(),
            // Start with all bits set, remove non-hits in the loop.
            all_hit_bitmask: MapTileAttribute::all_bits(),
        };

        // (128, 128) is top left for sprites
        for dx in 0..=(w + 7) / 8 {
            let px = x + (dx * 8).min(w);
            if !(128..448).contains(&px) {
                continue;
            }
            #[expect(clippy::cast_sign_loss)]
            for dy in 0..=(h + 7) / 8 {
                let py = y + (dy * 8).min(h);
                if !(128..368).contains(&py) {
                    continue;
                }

                if let Some(&attr) = self
                    .attr_layer
                    .get(((px - 128) / 8) as usize, ((py - 128) / 8) as usize)
                {
                    hit_tiles.any_hit_bitmask |= attr.into();
                    hit_tiles.all_hit_bitmask &= attr.into();
                }
            }
        }

        hit_tiles
    }
}

pub fn off_screen(x: i16, y: i16) -> bool {
    !(128..=320 + 128).contains(&x) || !(128..=224 + 128).contains(&y)
}
