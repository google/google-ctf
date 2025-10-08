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
use ufmt::derive::uDebug;

use crate::resource_state::State;

pub type SpriteInitializationFunction =
    fn(state: &mut State, vdp: &mut TargetVdp, keep_loaded: bool) -> BigSprite;

#[derive(uDebug)]
pub struct Frame {
    /// Offset within the tileset
    pub tile_offs: u16,
    /// Determines how long this frame should be shown on screen in screen refreshes.
    pub duration: u32,
}

pub struct Animation {
    pub loops: bool,
    pub frames: &'static [Frame],
}

impl ufmt::uDebug for Animation {
    fn fmt<W: ufmt::uWrite + ?Sized>(
        &self,
        writer: &mut ufmt::Formatter<'_, W>,
    ) -> Result<(), W::Error> {
        writer.write_str("<Animation>")
    }
}

#[derive(uDebug)]
pub struct AnimState {
    /// ID of the current active animation
    current_animation_id: usize,
    /// Frame index within the current active animation
    frame_index: usize,
    /// Tracks how much longer the current displayed frame should stay on
    /// screen before switching to the next one.
    frame_duration_remaining: u32,
}

impl AnimState {
    pub const fn new(anims: &[Animation]) -> AnimState {
        let frame_duration_remaining = if anims.is_empty() {
            0
        } else {
            anims[0].frames[0].duration
        };
        AnimState {
            current_animation_id: 0,
            frame_duration_remaining,
            frame_index: 0,
        }
    }
}

pub struct BigSprite {
    pub start_tile: u16,
    pub sprites: &'static [Sprite],
    pub anims: &'static [Animation],
    pub animation_state: AnimState,
    pub w: u16, // width in tiles
    pub h: u16, // height in tiles
    pub x: u16,
    pub y: u16,
    pub flip_v: bool,
    pub flip_h: bool,
}

impl ufmt::uDebug for BigSprite {
    fn fmt<W: ufmt::uWrite + ?Sized>(
        &self,
        writer: &mut ufmt::Formatter<'_, W>,
    ) -> Result<(), W::Error> {
        writer.write_str("<BigSprite>")
    }
}

impl BigSprite {
    pub fn new(
        res_state: &mut State,
        vdp: &mut TargetVdp,
        tiles_idx: usize,
        w: u16,
        h: u16,
        sprites: &'static [Sprite],
        anims: &'static [Animation],
        keep_loaded: bool,
    ) -> BigSprite {
        BigSprite {
            start_tile: res_state.load_tiles_to_vram(vdp, tiles_idx, keep_loaded),
            w,
            h,
            sprites,
            anims,
            animation_state: AnimState::new(anims),
            x: 0,
            y: 0,
            flip_v: false,
            flip_h: false,
        }
    }

    pub fn get_current_animation(&mut self) -> usize {
        self.animation_state.current_animation_id
    }

    pub fn maybe_set_anim(&mut self, id: usize) {
        if self.animation_state.current_animation_id != id {
            self.set_anim(id);
        }
    }

    pub fn set_anim(&mut self, id: usize) {
        self.animation_state = AnimState {
            current_animation_id: id,
            frame_duration_remaining: self.anims[id].frames[0].duration,
            frame_index: 0,
        };
    }

    /// Sets the sprite position while ensuring that out-of-bounds sprites don't wrap over.
    pub fn set_position(&mut self, x: i16, y: i16) {
        self.y = if y < 0 {
            0
        } else if y > 224 + 128 {
            224 + 128
        } else {
            y as u16
        };
        self.x = if x < 0 {
            0
        } else if x > 320 + 128 {
            320 + 128
        } else {
            x as u16
        };
    }

    pub fn render(&mut self, renderer: &mut impl Renderer) {
        let mut anim_offs = 0;
        if !self.anims.is_empty() {
            anim_offs = self.anims[self.animation_state.current_animation_id].frames
                [self.animation_state.frame_index]
                .tile_offs;
        }
        for s in self.sprites {
            let mut rs = s.clone();
            let base_tile = rs.flags().tile_index();
            rs.flags_mut()
                .set_tile_index(base_tile + self.start_tile + anim_offs)
                .set_flip_v(self.flip_v)
                .set_flip_h(self.flip_h);
            if self.flip_h {
                rs.x = self.w * 8 - rs.x - rs.w() * 8;
            }
            if self.flip_v {
                rs.y = self.h * 8 - rs.y - rs.h() * 8;
            }
            rs.x += self.x;
            rs.y += self.y;
            renderer.add_sprite(rs).unwrap();
        }
    }

    pub fn update(&mut self) {
        if self.anims.is_empty() {
            return;
        }
        let s = &mut self.animation_state;
        s.frame_duration_remaining -= 1;
        if s.frame_duration_remaining == 0 {
            s.frame_index += 1;
            if s.frame_index >= self.anims[s.current_animation_id].frames.len() {
                if self.anims[s.current_animation_id].loops {
                    s.frame_index = 0;
                } else {
                    s.frame_index = self.anims[s.current_animation_id].frames.len() - 1;
                }
            }
            s.frame_duration_remaining =
                self.anims[s.current_animation_id].frames[s.frame_index].duration;
        }
    }
}
