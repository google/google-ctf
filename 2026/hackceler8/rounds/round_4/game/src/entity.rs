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

use megahx8::*;

use crate::resource_state::State;

#[cfg_attr(feature = "tests", derive(Debug))]
#[derive(ufmt::derive::uDebug)]
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
    pub fn extend_by(&self, dx: i16, dy: i16) -> Hitbox {
        let new_x = self.x + dx;
        let new_y = self.y + dy;

        let x_min = self.x.min(new_x);
        let y_min = self.y.min(new_y);
        let x_max = (self.x + self.w).max(new_x + self.w);
        let y_max = (self.y + self.h).max(new_y + self.h);

        Hitbox {
            x: x_min,
            y: y_min,
            w: x_max - x_min,
            h: y_max - y_min,
        }
    }
}

pub trait Entity {
    fn hitbox(&self) -> Hitbox;
    fn render(&mut self, res_state: &mut State, vdp: &mut TargetVdp, renderer: &mut TargetRenderer);

    /// Sets the absolute position of the entity.
    fn set_position(&mut self, x: i16, y: i16);

    /// Move the entity relative to its current position.
    fn move_relative(&mut self, dx: i16, dy: i16);
}
