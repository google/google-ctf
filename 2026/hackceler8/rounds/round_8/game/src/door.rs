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

use crate::big_sprite::BigSprite;
use crate::entity::*;
use crate::game::Ctx;
use crate::res::maps;
use crate::res::sprites;
use crate::res::sprites::red_door_v_animated::Anim;
use crate::resource_state::State;

// Door dimensions, in pixels.
const WIDTH: i16 = 16;
const LENGTH: i16 = 48;

#[derive(Copy, Clone)]
pub enum Orientation {
    Horizontal,
    Vertical,
}

pub struct Door {
    pub x: i16,
    pub y: i16,
    sprite: BigSprite,
    pub id: u16,
    pub locked: bool,
    pub orientation: Orientation,
    pub open: bool,
    entry_side: Option<bool>,
}

/// Properties parsed from the map.
pub struct DoorProperties {
    /// A unique ID to idenfity the item within the given map.
    pub id: u16,
    pub locked: bool,
    pub orientation: Orientation,
}

impl Door {
    pub fn new(
        map_type: maps::MapType,
        map_x: i16,
        map_y: i16,
        properties: &DoorProperties,
        open: bool,
        locked: bool,
        res_state: &mut State,
        vdp: &mut TargetVdp,
    ) -> Door {
        let mut sprite_x = map_x + 128;
        let mut sprite_y = map_y + 128;
        match properties.orientation {
            Orientation::Horizontal => {
                sprite_x -= LENGTH / 2;
                sprite_y -= WIDTH / 2;
            }
            Orientation::Vertical => {
                sprite_x -= WIDTH / 2;
                sprite_y -= LENGTH / 2;
            }
        };
        let mut sprite = Self::get_sprite_init_fn(map_type, properties.orientation)(
            res_state, vdp, /* singleton= */ false, /* keep_loaded= */ false,
        );
        sprite.set_position(sprite_x, sprite_y);
        let mut door = Door {
            x: sprite_x,
            y: sprite_y,
            sprite,
            id: properties.id,
            locked: locked,
            orientation: properties.orientation,
            open,
            entry_side: None,
        };
        let anim = if open {
            Anim::Open
        } else if properties.locked {
            Anim::ClosedKeyhole
        } else {
            Anim::Closed
        };
        door.sprite.set_animation(anim as usize);
        door
    }

    pub fn update(ctx: &mut Ctx, door_id: usize) {
        let door = &mut ctx.map.doors[door_id];
        let unlocked = ctx.map.doors_unlocked.is_set(door.id);

        if !door.open && !door.locked {
            if door.sprite.current_animation() == (Anim::Opening as usize) {
                if door.sprite.is_animation_finished() {
                    door.open = true;
                }
            } else if ctx.player.is_active() {
                let hitbox = door.hitbox();
                let player_hitbox = ctx.player.hitbox();
                let opens = match door.orientation {
                    Orientation::Vertical => {
                        player_hitbox.offset(1, 0).collides(&hitbox)
                            || player_hitbox.offset(-1, 0).collides(&hitbox)
                    }
                    Orientation::Horizontal => {
                        player_hitbox.offset(0, 1).collides(&hitbox)
                            || player_hitbox.offset(0, -1).collides(&hitbox)
                    }
                };
                if opens {
                    door.open();
                }
            }
        } else if door.open {
            // Check if the player is crossing through the doors.
            let hitbox = door.hitbox();
            let player = &ctx.player;
            let player_hitbox = player.hitbox();
            let p_center = player_hitbox.center();
            let d_center = hitbox.center();
            let side = match door.orientation {
                Orientation::Vertical => p_center.0 > d_center.0,
                Orientation::Horizontal => p_center.1 > d_center.1,
            };
            if player_hitbox.collides(&hitbox) {
                if door.entry_side.is_none() {
                    door.entry_side = Some(side);
                }
            } else if let Some(entry_side) = door.entry_side {
                // Doors opened with a key don't close again.
                if !unlocked {
                    // Check if the player is still near.
                    let expanded_hitbox = hitbox.expand(16);
                    if player_hitbox.collides(&expanded_hitbox) {
                        if side != entry_side {
                            let id = door.id;
                            door.close_and_lock();
                            ctx.map.doors_unlocked.clear(id);
                            ctx.map.doors_locked.set(id);
                        }
                    } else {
                        // No player near, reset entry side.
                        door.entry_side = None;
                    }
                }
            }
        }

        door.sprite.update();
    }

    pub fn unlock(&mut self) {
        self.locked = false;
    }

    pub fn open(&mut self) {
        self.sprite.maybe_set_animation(Anim::Opening as usize);
    }

    pub fn close_and_lock(&mut self) {
        self.open = false;
        self.locked = true;
        self.entry_side = None;
        self.sprite.set_animation(Anim::Closed as usize);
    }

    fn get_sprite_init_fn(
        map_type: maps::MapType,
        orientation: Orientation,
    ) -> crate::big_sprite::SpriteInitializationFunction {
        match (map_type, orientation) {
            (maps::MapType::Arctic, Orientation::Horizontal) => sprites::blue_door_h_animated::new,
            (maps::MapType::Arctic, Orientation::Vertical) => sprites::blue_door_v_animated::new,
            (maps::MapType::Forest, Orientation::Horizontal) => sprites::green_door_h_animated::new,
            (maps::MapType::Forest, Orientation::Vertical) => sprites::green_door_v_animated::new,
            (maps::MapType::Spaceship, Orientation::Horizontal) => {
                sprites::white_door_h_animated::new
            }
            (maps::MapType::Spaceship, Orientation::Vertical) => {
                sprites::white_door_v_animated::new
            }
            (_, Orientation::Horizontal) => sprites::red_door_h_animated::new,
            (_, Orientation::Vertical) => sprites::red_door_v_animated::new,
        }
    }
}

impl Entity for Door {
    fn hitbox(&self) -> Hitbox {
        match self.orientation {
            Orientation::Horizontal => Hitbox {
                x: self.x,
                y: self.y,
                w: LENGTH,
                h: WIDTH,
            },
            Orientation::Vertical => Hitbox {
                x: self.x,
                y: self.y,
                w: WIDTH,
                h: LENGTH,
            },
        }
    }

    fn render(
        &mut self,
        res_state: &mut State,
        vdp: &mut TargetVdp,
        renderer: &mut TargetRenderer,
    ) {
        self.sprite.render(res_state, vdp, renderer);
    }

    #[expect(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    /// Set the absolute position of a sprite on the screen.
    fn set_position(&mut self, x: i16, y: i16) {
        self.x = x;
        self.y = y;
        self.sprite.set_position(x, y);
    }

    fn move_relative(&mut self, dx: i16, dy: i16) {
        self.set_position(self.x + dx, self.y + dy);
    }
}
