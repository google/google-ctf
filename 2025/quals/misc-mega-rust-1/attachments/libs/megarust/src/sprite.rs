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

use crate::Palette;

const TILE_FLAG_PRIORITY: u16 = 0x8000;
const TILE_FLAG_FLIP_H: u16 = 0x800;
const TILE_FLAG_FLIP_V: u16 = 0x1000;

/// A struct representing the display flags of a single tile.
///
/// This is shared between sprite definitions and tiles rendered on one of the 3
/// render planes.
#[derive(Clone, Copy, Debug, Default)]
pub struct TileFlags(pub(crate) u16);

impl TileFlags {
    /// Create a new flag with all values cleared.
    #[must_use]
    pub const fn new() -> TileFlags {
        TileFlags(0)
    }

    /// Create a new flag set for a given tile index.
    #[must_use]
    pub const fn for_tile(tile_idx: u16, palette: Palette) -> TileFlags {
        TileFlags(tile_idx | ((palette as u16) << 13))
    }

    /// Get the tile index these flags refer to.
    #[must_use]
    pub const fn tile_index(self) -> u16 {
        self.0 & 0x7ff
    }

    /// Set the tile index for these flags.
    #[must_use]
    pub fn set_tile_index(&mut self, tile_index: u16) -> &mut TileFlags {
        self.0 = (self.0 & 0xf800) | (tile_index & 0x7ff);

        self
    }

    /// Get the palette index these flags use.
    #[must_use]
    pub const fn palette(self) -> u8 {
        ((self.0 >> 13) & 3) as u8
    }

    /// Set the palette used by these flags.
    pub fn set_palette(&mut self, palette: Palette) -> &mut TileFlags {
        self.0 = (self.0 & 0x9fff) | ((palette as u16) << 13);

        self
    }

    /// Returns true if this tile will be rendered with priority.
    #[must_use]
    pub const fn priority(self) -> bool {
        (self.0 & TILE_FLAG_PRIORITY) != 0
    }

    /// Configure whether these flags render tiles with priority.
    pub fn set_priority(&mut self, p: bool) -> &mut TileFlags {
        if p {
            self.0 |= TILE_FLAG_PRIORITY;
        } else {
            self.0 &= !TILE_FLAG_PRIORITY;
        }

        self
    }

    /// Returns true if this tile is flipped horizontally.
    #[must_use]
    pub const fn flip_h(self) -> bool {
        (self.0 & TILE_FLAG_FLIP_H) != 0
    }

    /// Set whether these flags will render horizontally flipped tiles.
    pub fn set_flip_h(&mut self, p: bool) -> &mut TileFlags {
        if p {
            self.0 |= TILE_FLAG_FLIP_H;
        } else {
            self.0 &= !TILE_FLAG_FLIP_H;
        }

        self
    }

    /// Returns true if this tile is flipped vertically.
    #[must_use]
    pub const fn flip_v(self) -> bool {
        (self.0 & TILE_FLAG_FLIP_V) != 0
    }

    /// Set whether these flags will render vertically flipped tiles.
    pub fn set_flip_v(&mut self, p: bool) -> &mut TileFlags {
        if p {
            self.0 |= TILE_FLAG_FLIP_V;
        } else {
            self.0 &= !TILE_FLAG_FLIP_V;
        }

        self
    }
}

/// An enumeration of valid sprite sizes in tiles.
#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum SpriteSize {
    Size1x1 = 0b0000,
    Size2x1 = 0b0100,
    Size3x1 = 0b1000,
    Size4x1 = 0b1100,
    Size1x2 = 0b0001,
    Size2x2 = 0b0101,
    Size3x2 = 0b1001,
    Size4x2 = 0b1101,
    Size1x3 = 0b0010,
    Size2x3 = 0b0110,
    Size3x3 = 0b1010,
    Size4x3 = 0b1110,
    Size1x4 = 0b0011,
    Size2x4 = 0b0111,
    Size3x4 = 0b1011,
    Size4x4 = 0b1111,
}

impl SpriteSize {
    /// Get the `SpriteSize` given the width and height of the sprite in tiles.
    ///
    /// # Panics
    /// Will panic for invalid sprite size
    #[must_use]
    pub const fn for_size(w: u8, h: u8) -> SpriteSize {
        assert!((w <= 4) && (h <= 4), "invalid sprite size");
        unsafe { core::mem::transmute(((w - 1) << 2) | (h - 1)) }
    }

    /// Get the width in tiles given the `SpriteSize`.
    #[must_use]
    pub const fn w(s: SpriteSize) -> u8 {
        unsafe { (core::mem::transmute::<SpriteSize, u8>(s) >> 2) + 1 }
    }

    /// Get the width in tiles given the `SpriteSize`.
    #[must_use]
    pub const fn h(s: SpriteSize) -> u8 {
        unsafe { (core::mem::transmute::<SpriteSize, u8>(s) & 0b11) + 1 }
    }
}

/// A representation of the hardware sprites supported by the Mega Drive VDP.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct Sprite {
    pub y: u16,
    pub size: SpriteSize,
    pub link: u8,
    pub flags: TileFlags,
    pub x: u16,
}

impl Sprite {
    /// Create a new sprite with the given rendering flags.
    #[must_use]
    pub const fn with_flags(flags: TileFlags, size: SpriteSize) -> Self {
        Sprite {
            y: 0,
            size,
            link: 0,
            flags,
            x: 0,
        }
    }

    /// Fetch the rendering flags for this sprite.
    #[must_use]
    pub const fn flags(&self) -> TileFlags {
        self.flags
    }

    /// Get a mutable reference to this sprite's rendering flags.
    #[must_use]
    pub fn flags_mut(&mut self) -> &mut TileFlags {
        &mut self.flags
    }

    /// Set the rendering flags for this sprite.
    pub fn set_flags(&mut self, flags: TileFlags) {
        self.flags = flags;
    }

    #[must_use]
    pub const fn w(&self) -> u16 {
        SpriteSize::w(self.size) as u16
    }

    #[must_use]
    pub const fn h(&self) -> u16 {
        SpriteSize::h(self.size) as u16
    }
}

impl Default for Sprite {
    fn default() -> Self {
        Sprite {
            y: 0,
            size: SpriteSize::Size1x1,
            link: 0,
            flags: TileFlags::default(),
            x: 0,
        }
    }
}
