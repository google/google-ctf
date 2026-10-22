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
use ufmt::derive::uDebug;

use crate::resource_state::State;
use crate::resource_state::TileSlice;

pub type SpriteInitializationFunction =
    fn(state: &mut State, vdp: &mut TargetVdp, singleton: bool, keep_loaded: bool) -> BigSprite;

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
    /// If this counter is 0, the animation has finished.
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
    /// The start of the sprite's tiles in the VRAM.
    vram_start_tile: u16,
    /// The index of the sprite's tiles in the global tileset array.
    pub tiles_idx: usize,
    sprites: &'static [Sprite],
    anims: &'static [Animation],
    animation_state: AnimState,
    /// width and height in tiles
    w: u16,
    h: u16,
    pub x: u16,
    pub y: u16,
    pub flip_v: bool,
    pub flip_h: bool,
    pub priority: bool,
    /// Whether there's only one instance of this sprite on screen at a time.
    /// If true, only the frame currently being displayed is loaded which
    /// saves VRAM space
    pub singleton: bool,
    singleton_tile_offs: u16,
    /// Offset added to the frame's tile offset when rendering. This allows the sprite to
    /// dynamically swap its tileset/graphics while preserving the current animation state.
    /// E.g., used to select shooting equivalents of the player animations.
    pub tileset_shift: u16,
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
        singleton: bool,
        keep_loaded: bool,
    ) -> BigSprite {
        let subset_config = if singleton {
            // Singletons don't need all their animation to be loaded into VRAM,
            // only the first frame containing w*h tiles.
            Some(TileSlice {
                start: 0,
                len: (w * h) as usize,
            })
        } else {
            None
        };
        BigSprite {
            vram_start_tile: res_state.load_tiles_to_vram(
                vdp,
                tiles_idx,
                keep_loaded,
                subset_config,
            ),
            tiles_idx,
            w,
            h,
            sprites,
            anims,
            animation_state: AnimState::new(anims),
            x: 0,
            y: 0,
            flip_v: false,
            flip_h: false,
            priority: false,
            singleton,
            singleton_tile_offs: u16::MAX,
            tileset_shift: 0,
        }
    }

    pub fn current_animation(&self) -> usize {
        self.animation_state.current_animation_id
    }

    /// The first VRAM tile index occupied by this sprite's currently loaded tiles.
    pub fn vram_start_tile(&self) -> u16 {
        self.vram_start_tile
    }

    /// The sprite's size in tiles as `(width, height)`.
    pub fn tile_dimensions(&self) -> (u16, u16) {
        (self.w, self.h)
    }

    #[cfg(feature = "tests")]
    pub fn current_frame_index(&self) -> usize {
        self.animation_state.frame_index
    }

    pub fn next_frame(&self) -> usize {
        let s = &self.animation_state;
        if s.frame_duration_remaining == 1 {
            return s.frame_index + 1;
        }
        s.frame_index
    }

    pub fn is_animation_finished(&self) -> bool {
        let s = &self.animation_state;
        let anim = &self.anims[s.current_animation_id];
        !anim.loops && s.frame_duration_remaining == 0
    }

    pub fn maybe_set_animation(&mut self, id: usize) {
        if self.animation_state.current_animation_id != id {
            self.set_animation(id);
        }
    }

    pub fn set_animation(&mut self, id: usize) {
        if id >= self.anims.len() {
            return;
        }
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

    pub fn render(
        &mut self,
        res_state: &mut State,
        vdp: &mut TargetVdp,
        renderer: &mut TargetRenderer,
    ) {
        let mut animation_offs = 0;
        if !self.anims.is_empty() {
            let s = &self.animation_state;
            let new_offs = self.anims[s.current_animation_id].frames[s.frame_index].tile_offs
                + self.tileset_shift;
            if self.singleton {
                // Singletons only have their current frame's tiles loaded
                // so we update them whenever the frame changed.
                if self.singleton_tile_offs != new_offs {
                    self.singleton_tile_offs = new_offs;
                    res_state.update_tile_slice(
                        vdp,
                        self.tiles_idx,
                        TileSlice {
                            start: new_offs as usize,
                            len: (self.w * self.h) as usize,
                        },
                    )
                }
            } else {
                animation_offs = new_offs;
            }
        }
        for s in self.sprites {
            let mut rs = s.clone();
            let base_tile = rs.flags().tile_index();
            rs.flags_mut()
                .set_tile_index(base_tile + self.vram_start_tile + animation_offs)
                .set_flip_v(self.flip_v)
                .set_flip_h(self.flip_h)
                .set_priority(self.priority);
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
        if s.frame_duration_remaining == 0 {
            return;
        }

        s.frame_duration_remaining -= 1;
        if s.frame_duration_remaining == 0 {
            s.frame_index += 1;
            if s.frame_index >= self.anims[s.current_animation_id].frames.len() {
                if self.anims[s.current_animation_id].loops {
                    s.frame_index = 0;
                } else {
                    s.frame_index = self.anims[s.current_animation_id].frames.len() - 1;
                    return;
                }
            }
            s.frame_duration_remaining =
                self.anims[s.current_animation_id].frames[s.frame_index].duration;
        }
    }
}
