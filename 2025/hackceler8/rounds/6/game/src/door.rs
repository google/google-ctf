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

use crate::big_sprite::BigSprite;
use crate::entity::*;
use crate::res::maps;
use crate::res::sprites;
use crate::res::sprites::blue_door_h::Anim;
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
    orientation: Orientation,
    pub open: bool,
}

/// Properties parsed from the map.
pub struct DoorProperties {
    /// A unique ID to idenfity the item within the given world.
    pub id: u16,
    pub orientation: Orientation,
}

impl Door {
    pub fn new(
        world_type: maps::WorldType,
        map_x: i16,
        map_y: i16,
        properties: &DoorProperties,
        open: bool,
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
        let mut sprite = Self::get_sprite_init_fn(world_type, properties.orientation)(
            res_state, vdp, /* keep_loaded= */ false,
        );
        sprite.set_position(sprite_x, sprite_y);
        let mut door = Door {
            x: sprite_x,
            y: sprite_y,
            sprite,
            id: properties.id,
            orientation: properties.orientation,
            open,
        };
        door.sprite
            .set_anim(if open { Anim::Open } else { Anim::Closed } as usize);
        door
    }

    pub fn open(&mut self) {
        self.open = true;
        self.sprite.set_anim(Anim::Open as usize);
    }

    fn get_sprite_init_fn(
        world_type: maps::WorldType,
        orientation: Orientation,
    ) -> crate::big_sprite::SpriteInitializationFunction {
        match (world_type, orientation) {
            (maps::WorldType::Overworld, Orientation::Horizontal) => sprites::grey_door_h::new,
            (maps::WorldType::Overworld, Orientation::Vertical) => sprites::grey_door_v::new,
            (maps::WorldType::FireTemple, Orientation::Horizontal) => sprites::red_door_h::new,
            (maps::WorldType::FireTemple, Orientation::Vertical) => sprites::red_door_v::new,
            (maps::WorldType::WaterTemple, Orientation::Horizontal) => sprites::blue_door_h::new,
            (maps::WorldType::WaterTemple, Orientation::Vertical) => sprites::blue_door_v::new,
            (maps::WorldType::ForestTemple, Orientation::Horizontal) => sprites::green_door_h::new,
            (maps::WorldType::ForestTemple, Orientation::Vertical) => sprites::green_door_v::new,
            (maps::WorldType::SkyTemple, Orientation::Horizontal) => sprites::white_door_h::new,
            _ => sprites::white_door_v::new,
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

    fn render(&mut self, renderer: &mut TargetRenderer) {
        self.sprite.render(renderer);
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
