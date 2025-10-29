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

use crate::anim::{Anim, AnimState};
use crate::map::Map;
use crate::physics;
use crate::tiles;
use megarust::*;

pub struct Sonk {
    pub sprite: Sprite,
    anim_state: AnimState,
    pub speed_x: i16,
    pub speed_y: i16,
    on_ground: bool,
    pub damaged: bool,
    // Direction to fall to during the damage sequence.
    fall_left: bool,
}

impl Sonk {
    pub fn new() -> Self {
        let sprite = Sprite {
            size: SpriteSize::Size4x4,
            x: 248,
            y: 256,
            link: 0,
            flags: TileFlags::for_tile(tiles::SONK_TILE_OFFSET, Palette::A),
        };
        Sonk {
            sprite,
            anim_state: AnimState::new(),
            speed_x: 0,
            speed_y: 0,
            on_ground: true,
            damaged: false,
            fall_left: false,
        }
    }

    pub fn update(
        &mut self,
        map: &Map,
        vdp: &mut TargetVdp,
        controller: &mut TargetControllers,
        frame: u16,
    ) {
        let input = controller
            .controller_state(0)
            .expect("Can't controller state");

        if !self.damaged {
            if input.is_pressed(Button::Left) {
                if self.speed_x > -120 {
                    self.speed_x -= 2;
                }
                self.sprite.flags_mut().set_flip_h(true);
            } else if input.is_pressed(Button::Right) {
                if self.speed_x < 120 {
                    self.speed_x += 2;
                }
                self.sprite.flags_mut().set_flip_h(false);
            }
        }

        if self.on_ground {
            self.damaged = false;
            if input.just_pressed(Button::Up) {
                self.on_ground = false;
                self.speed_y = -30;
            } else {
                self.speed_y = 0;
            }
        } else {
            self.speed_y = (self.speed_y + 1).min(100);
        }
        if self.speed_x.abs() > 0 {
            self.speed_x -= self.speed_x.signum();
        }

        self.mov(frame);
        self.ground_collision_check(map, vdp);

        self.update_anim(
            input.is_pressed(Button::Left),
            input.is_pressed(Button::Right),
        );
    }

    pub fn is_rolling(&self) -> bool {
        return self.anim_state.get_anim() == Anim::Jump;
    }

    pub fn on_hit(&mut self, fall_left: bool) {
        self.damaged = true;
        self.fall_left = fall_left;
        self.sprite.flags_mut().set_flip_h(!fall_left);
        self.on_ground = false;
        self.speed_x = 0;
        self.speed_y = -30;
    }

    pub fn render(&mut self, frame: u16, renderer: &mut TargetRenderer) {
        if self.damaged && (frame / 5) % 2 == 0 {
            // Blink effect
            return;
        }
        renderer
            .add_sprite(self.anim_state.get_sprite(&self.sprite))
            .unwrap();
    }

    fn mov(&mut self, frame: u16) {
        self.sprite.x = (self.sprite.x as i32 + (self.speed_x / 10) as i32) as u16;
        let decimal = self.speed_x % 10;
        if frame % 10 <= decimal.abs() as u16 {
            self.sprite.x = (self.sprite.x as i32 + decimal.signum() as i32) as u16;
        }

        self.sprite.y = (self.sprite.y as i32 + (self.speed_y / 10) as i32) as u16;
        let decimal = self.speed_y % 10;
        if frame % 10 <= decimal.abs() as u16 {
            self.sprite.y = (self.sprite.y as i32 + decimal.signum() as i32) as u16;
        }

        if self.damaged {
            if self.fall_left {
                self.sprite.x -= 2;
            } else {
                self.sprite.x += 2;
            }
        }
    }

    fn ground_collision_check(&mut self, map: &Map, vdp: &mut TargetVdp) {
        let mid_x = self.sprite.x as i16 + 16 - 128;
        let ground_y = physics::get_ground_y(mid_x, map, vdp);
        if self.on_ground || self.sprite.y - 128 + 32 >= ground_y {
            self.speed_y = ground_y as i16 + 128 - 32 - self.sprite.y as i16;
            self.sprite.y = ground_y + 128 - 32;
            self.on_ground = true;
        } else {
            self.on_ground = false;
        }
    }

    fn update_anim(&mut self, left_pressed: bool, right_pressed: bool) {
        let curr_anim = self.anim_state.get_anim();
        let run_anim = curr_anim == Anim::Run1
            || curr_anim == Anim::Run2
            || curr_anim == Anim::Run3
            || curr_anim == Anim::Run4;
        if run_anim {
            self.anim_state
                .update((self.speed_x.abs() / 2).min(70) as u32);
        } else {
            self.anim_state.update(10);
        }

        if self.damaged {
            self.anim_state.maybe_set_anim(Anim::Damage);
        } else if !self.on_ground {
            self.anim_state.maybe_set_anim(Anim::Jump);
        } else if self.speed_x == 0 {
            self.anim_state.maybe_set_anim(Anim::Idle);
        } else if self.speed_x > 0 && left_pressed {
            self.anim_state.maybe_set_anim(Anim::Brake);
        } else if self.speed_x < 0 && right_pressed {
            self.anim_state.maybe_set_anim(Anim::Brake);
        } else {
            let new_anim = if self.speed_x.abs() < 30 {
                Anim::Run1
            } else if self.speed_x.abs() < 60 {
                Anim::Run2
            } else if self.speed_x.abs() < 90 {
                Anim::Run3
            } else {
                Anim::Run4
            };
            if !run_anim {
                self.anim_state.set_anim(new_anim);
            } else {
                self.anim_state.set_anim_keep_frame(new_anim);
            }
        }
    }
}
