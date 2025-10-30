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

use crate::sprite::Sprite;
use crate::Error;

pub const MAX_SPRITES: usize = 256;

#[cfg(target_arch = "m68k")]
pub(crate) mod m68k;

pub trait Renderer {
    type Vdp;

    /// Clear the sprite buffer.
    fn clear(&mut self);

    /// Add sprite to the sprite buffer.
    ///
    /// # Errors
    /// Returns error if sprite buffer size is exceeded.
    fn add_sprite(&mut self, s: Sprite) -> Result<(), Error>;

    /// Draw all registered sprites
    fn render(&mut self, vdp: &mut Self::Vdp);
}
