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

pub struct Spike {
    pub sprite: Sprite,
}

impl Spike {
    pub fn new(x: u16, y: u16) -> Self {
        let sprite = Sprite {
            size: SpriteSize::Size3x3,
            x: x,
            y: y,
            link: 0,
            flags: TileFlags::for_tile(tiles::SPIKE_TILE_OFFSET, Palette::B),
        };
        Spike { sprite }
    }

    pub fn update(&mut self, sonk: &mut Sonk, frame: u16) {
        self.attack(sonk);
        self.update_anim(frame);
    }

    pub fn render(&mut self, renderer: &mut TargetRenderer) {
        renderer.add_sprite(self.sprite.clone()).unwrap();
    }

    pub fn off_screen(x: i16, y: i16) -> bool {
        x + 19 < 128 || x > 128 + 320 || y + 19 < 128 || y > 128 + 224
    }

    pub fn on_screen(x: i16, y: i16) -> bool {
        x + 19 >= 128 && x <= 128 + 320 && y + 19 >= 128 && y <= 128 + 224
    }

    fn attack(&mut self, sonk: &mut Sonk) {
        if sonk.sprite.x + 8 >= self.sprite.x + 17
            || sonk.sprite.x + 16 <= self.sprite.x + 1
            || sonk.sprite.y + 8 >= self.sprite.y + 17
            || sonk.sprite.y + 32 <= self.sprite.y + 1
        {
            // Not colliding
            return;
        }
        sonk.on_hit(sonk.sprite.x + 6 < self.sprite.x);
    }

    fn update_anim(&mut self, frame: u16) {
        let tile = tiles::SPIKE_TILE_OFFSET
            + if frame % 240 < 220 {
                0
            } else if frame % 240 < 225 {
                9
            } else if frame % 240 < 235 {
                18
            } else {
                9
            };
        let _ = self.sprite.flags_mut().set_tile_index(tile);
    }
}
