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
use crate::game::Ctx;
use crate::res::items;
use crate::res::items::ItemType;
use crate::resource_state::State;
use crate::Player;

const HITBOX_W: i16 = 16;
const HITBOX_H: i16 = 8;

pub struct Item {
    pub x: i16,
    pub y: i16,
    pub sprite: BigSprite,
    pub item_type: ItemType,
    pub id: u16,
    pub collected: bool,
}

/// Item properties parsed from the map.
pub struct ItemProperties {
    /// A unique ID to idenfity the item within the given world.
    pub id: u16,
}

impl Item {
    pub fn new(
        item_type: ItemType,
        map_x: i16,
        map_y: i16,
        properties: &ItemProperties,
        res_state: &mut State,
        vdp: &mut TargetVdp,
    ) -> Item {
        let sprite_x = map_x + 128 - HITBOX_W / 2;
        let sprite_y = map_y + 128 - HITBOX_H / 2;
        let mut sprite =
            items::sprite_init_fn(item_type)(res_state, vdp, /* keep_loaded= */ false);
        sprite.set_position(sprite_x, sprite_y);
        Item {
            x: sprite_x,
            y: sprite_y,
            sprite,
            item_type,
            id: properties.id,
            collected: false,
        }
    }

    // Runs an item tick. Returns the ID of the item collected and the type of
    // the item that should be added to the inventory, if any.
    pub fn update(ctx: &mut Ctx, item_id: usize) -> (Option<u16>, Option<ItemType>) {
        let item = &mut ctx.world.items[item_id];
        if item.collected {
            return (None, None);
        }
        for player in &mut ctx.players {
            if !player.is_active() {
                continue;
            }
            if item.hitbox().collides(&player.hitbox()) {
                item.collected = true;
                if item.apply_immediate_effects(player) {
                    // Items with immediate effects don't get
                    // added to the inventory.
                    return (Some(item.id), None);
                }
                return (Some(item.id), Some(item.item_type));
            }
        }
        (None, None)
    }

    /// Returns true if the item should be unloaded from memory.
    pub fn should_unload(&self) -> bool {
        self.collected
    }

    /// Applies the item's immediate effects to the player who collected it.
    /// Returns false if there was no immediate effect to apply.
    pub fn apply_immediate_effects(&self, player: &mut Player) -> bool {
        match self.item_type {
            ItemType::HeartItem => {
                if player.health < player.max_health {
                    player.health += 1;
                }
            }
            _ => {
                return false;
            }
        }
        true
    }
}

impl Entity for Item {
    fn hitbox(&self) -> Hitbox {
        Hitbox {
            x: self.x,
            y: self.y,
            w: HITBOX_W,
            h: HITBOX_H,
        }
    }

    fn render(&mut self, renderer: &mut TargetRenderer) {
        self.sprite.render(renderer);
    }

    #[expect(clippy::cast_sign_loss)]
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
