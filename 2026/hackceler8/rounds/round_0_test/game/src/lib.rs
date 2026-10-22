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

#![no_std]

use ufmt::derive::uDebug;

mod big_sprite;
mod data;
mod dialogue;
mod door;
mod enemy;
mod entity;
mod fader;
pub mod game;
mod image;
mod inventory;
mod item;
mod map;
mod map_data;
mod npc;
mod physics;
mod placement;
mod player;
mod projectile;
pub mod res;
mod stage_select;
mod switch;
mod ui;
mod walk;
mod weapon;

pub(crate) mod resource_state;

pub(crate) use dialogue::Dialogue;
pub(crate) use door::Door;
pub use enemy::Enemy;
pub use entity::Entity;
pub use entity::Hitbox;
pub use game::Ctx;
pub use game::Game;
pub(crate) use inventory::Inventory;
pub(crate) use inventory::InventoryScene;
pub(crate) use item::Item;
pub use map::Bitmask;
pub use map::Map;
pub use res::maps::MAP_COUNT;
pub(crate) use map_data::HitTiles;
pub(crate) use map_data::MapData;
pub(crate) use npc::Npc;
pub(crate) use player::Player;
pub use player::PlayerType;
pub use player::Status;
pub(crate) use projectile::Projectile;
pub(crate) use stage_select::StageSelect;
pub(crate) use switch::Switch;
pub(crate) use ui::UI;

#[cfg(feature = "tests")]
pub use enemy::EnemyProperties;

#[cfg_attr(feature = "tests", derive(Debug))]
#[derive(PartialEq, uDebug, Copy, Clone)]
pub enum Direction {
    Up,
    Down,
    Left,
    Right,
}

impl Direction {
    /// Returns a coordinate offset for the given direction with
    /// a length of 1.
    pub(crate) fn to_offset(self) -> (i16, i16) {
        match self {
            Direction::Up => (0, -1),
            Direction::Down => (0, 1),
            Direction::Left => (-1, 0),
            Direction::Right => (1, 0),
        }
    }
}

#[derive(Copy, Clone)]
pub struct PlaneAddress(u16, u16);

impl PlaneAddress {
    pub fn new(x: u16, y: u16) -> Self {
        assert!(x < 64);
        assert!(y < 64);
        Self(x, y)
    }

    fn normalize(mut self) -> Self {
        self.0 %= 64;
        self.1 %= 64;
        self
    }

    // Convert to flat address space
    pub fn to_address(&self) -> u16 {
        self.0 + self.1 * 64
    }
}

impl core::ops::Add<(u16, u16)> for PlaneAddress {
    type Output = Self;

    fn add(self, rhs: (u16, u16)) -> Self::Output {
        Self(self.0 + rhs.0, self.1 + rhs.1).normalize()
    }
}

impl core::ops::Add<(i16, i16)> for PlaneAddress {
    type Output = Self;

    fn add(self, rhs: (i16, i16)) -> Self::Output {
        Self(
            self.0.wrapping_add(rhs.0 as u16),
            self.1.wrapping_add(rhs.1 as u16),
        )
        .normalize()
    }
}

/// A "view" into VDP plane memory
pub struct PlaneWindow {
    /// Current scroll offset
    scroll: (i16, i16),
}

impl PlaneWindow {
    fn new() -> Self {
        Self { scroll: (0, 0) }
    }

    /// Returns the VRAM address of the top left tile
    /// for the current scroll
    pub fn vram_address(&self) -> PlaneAddress {
        let x = self.current_scroll_in_tiles();
        PlaneAddress(x.0, x.1)
    }

    // Make sure that self.scroll is in the range of (0..64 * 8),(0..64 * 8)
    fn normalize(&mut self) {
        self.scroll.0 %= 64 * 8;
        if self.scroll.0 < 0 {
            self.scroll.0 += 64 * 8;
        }
        self.scroll.1 %= 64 * 8;
        if self.scroll.1 < 0 {
            self.scroll.1 += 64 * 8;
        }
    }

    /// Scroll the window by the given amount
    pub fn scroll(&mut self, dx: i16, dy: i16) {
        self.scroll.0 += dx;
        self.scroll.1 += dy;
        self.normalize();
    }

    /// Returns the current scroll in pixel
    pub fn current_scroll(&self) -> (u16, u16) {
        (self.scroll.0 as u16, self.scroll.1 as u16)
    }

    /// Returns the current scroll in tiles (rounding down)
    pub fn current_scroll_in_tiles(&self) -> (u16, u16) {
        (self.scroll.0 as u16 / 8, self.scroll.1 as u16 / 8)
    }
}
