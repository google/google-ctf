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

pub struct Wasp {
    pub sprite: Sprite,
    frame: u16,
    death_timer: u16,
}

impl Wasp {
    pub fn new(x: u16, y: u16) -> Self {
        let sprite = Sprite {
            size: SpriteSize::Size4x3,
            x: x,
            y: y,
            link: 0,
            flags: *TileFlags::for_tile(tiles::WASP_TILE_OFFSET, Palette::B).set_flip_h(true),
        };
        Wasp {
            sprite,
            frame: 0,
            death_timer: 0,
        }
    }

    pub fn update(&mut self, sonk: &mut Sonk) {
        if self.death_timer > 0 {
            self.death_timer -= 1;
            if self.death_timer == 0 {
                self.sprite.x = 128 + 330; // Hacky way to unload
            }
            return;
        }
        self.frame += 1;
        self.mov();
        self.attack(sonk);
        self.update_anim();
    }

    pub fn render(&mut self, renderer: &mut TargetRenderer) {
        renderer.add_sprite(self.sprite.clone()).unwrap();
    }

    pub fn off_screen(x: i16, y: i16) -> bool {
        x + 32 <= 128 || x >= 128 + 320 || y + 24 < 128 || y > 128 + 224
    }

    pub fn on_screen(x: i16, y: i16) -> bool {
        x + 32 >= 128 && x <= 128 + 320 && y + 24 >= 128 && y <= 128 + 224
    }

    fn mov(&mut self) {
        if self.frame % 120 == 0 {
            let flip_h = !self.sprite.flags().flip_h();
            self.sprite.flags_mut().set_flip_h(flip_h);
        }
        if self.sprite.flags_mut().flip_h() {
            self.sprite.x -= 1;
        } else {
            self.sprite.x += 1;
        }
    }

    fn attack(&mut self, sonk: &mut Sonk) {
        if sonk.sprite.x + 8 >= self.sprite.x + 32
            || sonk.sprite.x + 16 <= self.sprite.x
            || sonk.sprite.y + 8 >= self.sprite.y + 24
            || sonk.sprite.y + 32 <= self.sprite.y
        {
            // Not colliding
            return;
        }
        if sonk.is_rolling() {
            self.on_hit();
            if sonk.sprite.y + 20 < self.sprite.y {
                sonk.speed_y = -30;
            } else if sonk.sprite.y > self.sprite.y + 4 {
                sonk.speed_y = 30;
            } else if sonk.sprite.x + 4 < self.sprite.x {
                sonk.speed_x = -30;
            } else if sonk.sprite.x > self.sprite.x + 12 {
                sonk.speed_x = 30;
            }
        } else {
            sonk.on_hit(sonk.sprite.x < self.sprite.x);
        }
    }

    pub fn on_hit(&mut self) {
        self.death_timer = 60;
        self.sprite.flags_mut().set_palette(Palette::C);
    }

    fn update_anim(&mut self) {
        if self.frame % 5 == 0 {
            let mut tile = tiles::WASP_TILE_OFFSET;
            if self.frame % 10 == 0 {
                tile += 12;
            }
            let _ = self.sprite.flags_mut().set_tile_index(tile);
        }
    }
}
