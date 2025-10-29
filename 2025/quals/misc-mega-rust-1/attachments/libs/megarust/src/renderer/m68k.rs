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

use crate::Error;

pub struct Renderer {
    num_sprites: usize,
    sprites: [super::Sprite; super::MAX_SPRITES],
}

impl Default for Renderer {
    fn default() -> Self {
        Self {
            num_sprites: 0,
            sprites: unsafe { core::mem::MaybeUninit::zeroed().assume_init() },
        }
    }
}

impl super::Renderer for Renderer {
    type Vdp = crate::vdp::m68k::Vdp;

    fn clear(&mut self) {
        self.num_sprites = 0;
    }

    fn add_sprite(&mut self, sprite: super::Sprite) -> Result<(), Error> {
        if self.num_sprites < super::MAX_SPRITES {
            self.sprites[self.num_sprites] = sprite;
            self.num_sprites += 1;
            Ok(())
        } else {
            Err(Error::BufferSizeExceeded)
        }
    }

    fn render(&mut self, vdp: &mut Self::Vdp) {
        let num_sprites = self.num_sprites;
        let sprites = &mut self.sprites[..num_sprites];

        for (idx, s) in sprites.iter_mut().enumerate() {
            let next = if idx < num_sprites - 1 {
                (idx + 1) as u8
            } else {
                0
            };
            s.link = next;
        }

        vdp.set_sprites(0, sprites);
    }
}
