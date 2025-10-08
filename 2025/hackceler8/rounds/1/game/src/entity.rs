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

pub struct Hitbox {
    pub x: i16,
    pub y: i16,
    pub w: i16,
    pub h: i16,
}

impl Hitbox {
    pub fn center(&self) -> (i16, i16) {
        (self.x + self.w / 2, self.y + self.h / 2)
    }
    pub fn collides(&self, o: &Hitbox) -> bool {
        self.x < o.x + o.w && self.x + self.w > o.x && self.y < o.y + o.h && self.y + self.h > o.y
    }
    pub fn offset(&self, dx: i16, dy: i16) -> Hitbox {
        Hitbox {
            x: self.x + dx,
            y: self.y + dy,
            w: self.w,
            h: self.h,
        }
    }
    pub fn expand(&self, amount: i16) -> Hitbox {
        Hitbox {
            x: self.x - amount,
            y: self.y - amount,
            w: self.w + amount * 2,
            h: self.h + amount * 2,
        }
    }
}

pub trait Entity {
    fn hitbox(&self) -> Hitbox;
    fn render(&mut self, renderer: &mut TargetRenderer);

    /// Sets the absolute position of the entity.
    fn set_position(&mut self, x: i16, y: i16);

    /// Move the entity relative to its current position.
    fn move_relative(&mut self, dx: i16, dy: i16);
}
