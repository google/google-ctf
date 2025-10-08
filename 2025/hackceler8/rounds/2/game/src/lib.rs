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
mod npc;
mod physics;
mod player;
mod projectile;
mod res;
mod switch;
mod ui;
mod walk;
mod world;

pub(crate) mod resource_state;

pub(crate) use dialogue::Dialogue;
pub(crate) use door::Door;
pub(crate) use enemy::Enemy;
pub use game::Game;
pub(crate) use inventory::Inventory;
pub(crate) use inventory::InventoryScene;
pub(crate) use item::Item;
pub(crate) use map::HitTiles;
pub(crate) use map::Map;
pub(crate) use npc::Npc;
pub(crate) use player::Player;
pub(crate) use projectile::Projectile;
pub(crate) use switch::Switch;
pub(crate) use ui::UI;
pub(crate) use world::World;

#[derive(PartialEq, uDebug, Copy, Clone)]
pub(crate) enum Direction {
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

    // This function can probably be dropped and implemented in a nicer way.
    /// Returns the scroll values for the current scroll + an offset
    fn offset(&self, delta: (i16, i16)) -> (u16, u16) {
        let mut x = PlaneWindow {
            scroll: (self.scroll.0 + delta.0, self.scroll.1 + delta.1),
        };
        x.normalize();
        x.current_scroll()
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
