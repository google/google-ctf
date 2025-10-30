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

use crate::tiles;
use megarust::*;

struct Frames {
    pub tile_offs: u16,
    pub len: u16,
    pub duration: u32,
}

struct Animation {
    pub loops: bool,
    pub frames: Frames,
}

#[derive(Copy, Clone, PartialEq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum Anim {
    Brake,
    Damage,
    Idle,
    Jump,
    Run1,
    Run2,
    Run3,
    Run4,
}

const ANIMS: &[Animation] = &[
    Animation {
        loops: false,
        frames: Frames {
            tile_offs: 64,
            len: 2,
            duration: 150,
        },
    },
    Animation {
        loops: false,
        frames: Frames {
            tile_offs: 736,
            len: 2,
            duration: 150,
        },
    },
    Animation {
        loops: true,
        frames: Frames {
            tile_offs: 0,
            len: 4,
            duration: 70,
        },
    },
    Animation {
        loops: true,
        frames: Frames {
            tile_offs: 672,
            len: 4,
            duration: 35,
        },
    },
    Animation {
        loops: true,
        frames: Frames {
            tile_offs: 128,
            len: 8,
            duration: 70,
        },
    },
    Animation {
        loops: true,
        frames: Frames {
            tile_offs: 256,
            len: 8,
            duration: 70,
        },
    },
    Animation {
        loops: true,
        frames: Frames {
            tile_offs: 384,
            len: 8,
            duration: 70,
        },
    },
    Animation {
        loops: true,
        frames: Frames {
            tile_offs: 512,
            len: 8,
            duration: 70,
        },
    },
];

pub struct AnimState {
    curr_anim: Anim,
    frames_left: u32,
    curr_frame: u16,
}

impl AnimState {
    pub const fn new() -> AnimState {
        let frames_left = ANIMS[0].frames.duration;
        AnimState {
            curr_anim: Anim::Idle,
            frames_left,
            curr_frame: 0,
        }
    }

    pub fn maybe_set_anim(&mut self, id: Anim) {
        if self.curr_anim != id {
            self.set_anim(id);
        }
    }

    pub fn set_anim(&mut self, id: Anim) {
        self.curr_anim = id;
        self.frames_left = ANIMS[id as usize].frames.duration;
        self.curr_frame = 0;
    }

    pub fn get_anim(&self) -> Anim {
        return self.curr_anim;
    }

    pub fn set_anim_keep_frame(&mut self, id: Anim) {
        self.curr_anim = id;
    }

    pub fn update(&mut self, frames: u32) {
        if self.frames_left <= frames {
            self.curr_frame += 1;
            if self.curr_frame >= ANIMS[self.curr_anim as usize].frames.len {
                if ANIMS[self.curr_anim as usize].loops {
                    self.curr_frame = 0;
                } else {
                    self.curr_frame = ANIMS[self.curr_anim as usize].frames.len - 1;
                }
            }
            self.frames_left = ANIMS[self.curr_anim as usize].frames.duration;
        }
        self.frames_left -= frames;
    }

    pub fn get_sprite(&self, sprite: &Sprite) -> Sprite {
        let tile_offs = ANIMS[self.curr_anim as usize].frames.tile_offs + self.curr_frame * 16;
        let mut s = sprite.clone();
        let _ = s
            .flags_mut()
            .set_tile_index(tiles::SONK_TILE_OFFSET + tile_offs);
        return s;
    }
}
