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

use crate::sonk::Sonk;
use crate::tiles;
use megarust::*;

pub struct Flag {
    pub id: u8,
    pub x: u16,
    pub y: u16,
    pub sprite: Sprite,
}

impl Flag {
    pub fn new(id: u8, x: u16, y: u16) -> Self {
        let sprite = Sprite {
            size: SpriteSize::Size2x2,
            x: x,
            y: y,
            link: 0,
            flags: TileFlags::for_tile(tiles::FLAG_TILE_OFFSET, Palette::B),
        };
        Flag { id, x, y, sprite }
    }

    pub fn update(&mut self, sonk: &Sonk, frame: u16) -> bool {
        self.update_anim(frame);
        return self.colliding(sonk);
    }

    pub fn render(&mut self, renderer: &mut TargetRenderer) {
        renderer.add_sprite(self.sprite.clone()).unwrap();
    }

    fn colliding(&self, sonk: &Sonk) -> bool {
        if sonk.damaged {
            return false;
        }
        sonk.sprite.x + 8 < self.x + 14
            && sonk.sprite.x + 16 > self.x + 1
            && sonk.sprite.y + 8 < self.y + 2
            && sonk.sprite.y + 32 > self.y
    }

    fn update_anim(&mut self, frame: u16) {
        let tile = tiles::FLAG_TILE_OFFSET + ((frame % 48) / 8) * 4;
        let _ = self.sprite.flags_mut().set_tile_index(tile);
    }
}
