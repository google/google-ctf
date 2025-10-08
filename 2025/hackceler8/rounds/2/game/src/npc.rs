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

use core::fmt::Write;

use crate::res::tileset;
use heapless::String;
use heapless::Vec;
use megahx8::*;

use crate::big_sprite::BigSprite;
use crate::entity::*;
use crate::game::Ctx;
use crate::image;
use crate::inventory::InventoryItem;
use crate::res::items::ItemType;
use crate::res::npcs;
use crate::res::npcs::NpcType;
use crate::res::sprites::racoon_npc as Sprite;
use crate::resource_state::State;
use crate::ui;
use crate::Dialogue;

pub const DIALOGUES: &[fn() -> Dialogue] = &[
    example_dialogue, // 0
    bark_bark,        // 1
    fashion_advice,   // 2
    engrave,          // 3
];

// Note: The secret is different on the live console!
const SECRET: &str = "TEST_SECRET";

/// NPCs are friendly entities on the map that the player can talk to.
pub struct Npc {
    pub x: i16,
    pub y: i16,
    pub sprite: BigSprite,
    pub npc_type: NpcType,
    pub dialogue_id: u16,
    pub collected: bool,
}

/// NPC properties parsed from the map.
pub struct NpcProperties {
    /// A unique ID of the dialogue that this NPC has.
    pub dialogue_id: u16,
}

impl Npc {
    pub fn new(
        npc_type: NpcType,
        map_x: i16,
        map_y: i16,
        properties: &NpcProperties,
        res_state: &mut State,
        vdp: &mut TargetVdp,
    ) -> Npc {
        let center = Self::hitbox_for_type(npc_type).center();
        let sprite_x = map_x + 128 - center.0;
        let sprite_y = map_y + 128 - center.1;
        let mut sprite =
            npcs::sprite_init_fn(npc_type)(res_state, vdp, /* keep_loaded= */ false);
        sprite.set_position(sprite_x, sprite_y);
        sprite.set_anim(Sprite::Anim::IdleDown as usize);
        Npc {
            x: sprite_x,
            y: sprite_y,
            sprite,
            npc_type,
            dialogue_id: properties.dialogue_id,
            collected: false,
        }
    }

    /// Runs an NPC tick.
    pub fn update(ctx: &mut Ctx, npc_id: usize) {
        let mut dialogue_id = None;
        {
            let npc = &mut ctx.world.npcs[npc_id];
            let hitbox = npc.hitbox();
            for p in 0..ctx.players.len() {
                let player_hitbox = &mut ctx.players[p].hitbox();
                let input = &mut ctx.controller.controller_state(p);
                if let Some(input) = input {
                    // Talk to player if they're close enough and pressed the dialogue button.
                    if !(input.just_pressed(Button::B) && player_hitbox.expand(5).collides(&hitbox))
                    {
                        continue;
                    }
                    ctx.dialogue_player = p;
                    dialogue_id = Some(npc.dialogue_id);
                    // Face the player.
                    let center = hitbox.center();
                    let player_center = player_hitbox.center();
                    let dx = (center.0 - player_center.0) as i32;
                    let dy = (center.1 - player_center.1) as i32;
                    let (anim, flip) = if dx.abs() > dy.abs() {
                        if dx < 0 {
                            (Sprite::Anim::IdleRight, false)
                        } else {
                            (Sprite::Anim::IdleRight, true)
                        }
                    } else if dy > 0 {
                        (Sprite::Anim::IdleUp, false)
                    } else {
                        (Sprite::Anim::IdleDown, false)
                    };
                    npc.sprite.maybe_set_anim(anim as usize);
                    npc.sprite.flip_h = flip;
                    break;
                }
            }
        }
        if let Some(dialogue_id) = dialogue_id {
            ctx.start_dialogue(DIALOGUES[dialogue_id as usize]());
        }
    }

    fn hitbox_for_type(npc_type: NpcType) -> Hitbox {
        match npc_type {
            NpcType::RacoonNpc => Hitbox {
                x: 1,
                y: 10,
                w: 21,
                h: 21,
            },
            NpcType::DuckNpc => Hitbox {
                x: 2,
                y: 9,
                w: 28,
                h: 23,
            },
            NpcType::CatNpc => Hitbox {
                x: 4,
                y: 2,
                w: 9,
                h: 14,
            },
            NpcType::SnakeNpc => Hitbox {
                x: 1,
                y: 9,
                w: 13,
                h: 21,
            },
            NpcType::DogNpc => Hitbox {
                x: 5,
                y: 1,
                w: 15,
                h: 23,
            },
        }
    }
}

/// Functions for an example dialogue flow.
fn example_dialogue() -> Dialogue {
    Dialogue::new_multiple_choice(
        "GoogleCTF is my favourite CTF!",
        &["I agree", "I don't agree", "It depends", "Yes", "No"],
        Some(example_dialogue_2),
    )
}

fn example_dialogue_2(ctx: &mut Ctx, response: &str) {
    let mut text: String<100> = String::new();
    let _ = write!(
        text,
        "Thanks for responding with \"{}\"!\nWhat's your name?",
        response
    );
    ctx.start_dialogue(Dialogue::new_free_text(&text, Some(example_dialogue_3)));
}

fn example_dialogue_3(ctx: &mut Ctx, response: &str) {
    let mut text: String<100> = String::new();
    let _ = write!(text, "Hello {}!", response);
    ctx.start_dialogue(Dialogue::new_no_response(&text, None));
}

fn bark_bark() -> Dialogue {
    Dialogue::new_no_response("BARK BARK!", None)
}

fn fashion_advice() -> Dialogue {
    Dialogue::new_multiple_choice(
        "Would you like to hear my expert opinion on which item you should wear?",
        &["Yes", "No"],
        Some(fashion_advice_2),
    )
}

fn fashion_advice_2(ctx: &mut Ctx, response: &str) {
    if eq(response, "No") {
        return;
    }

    let fashion_id = get_random_wearable_id(ctx);
    if fashion_id.is_none() {
        ctx.start_dialogue(Dialogue::new_no_response(
            "It doesn't look like you have anything to wear.",
            None,
        ));
        return;
    }
    let fashion_id = fashion_id.unwrap();

    // Unequip previous items and equip the fashionable one. Looking sharp!
    for i in &mut ctx.world.inventory.items {
        if i.worn_by == Some(ctx.dialogue_player) {
            i.remove_effect(&mut ctx.players[ctx.dialogue_player]);
            i.worn_by = None;
        }
    }
    let fashion_item = &mut ctx.world.inventory.items[fashion_id];
    fashion_item.apply_effect(&mut ctx.players[ctx.dialogue_player]);
    fashion_item.worn_by = Some(ctx.dialogue_player);

    let mut text: String<64> = String::new();
    let _ = write!(
        text,
        "<{}> definitely looks best on you!",
        fashion_item.display_name()
    );
    ctx.start_dialogue(Dialogue::new_no_response(&text, None))
}

fn get_random_wearable_id(ctx: &mut Ctx) -> Option<usize> {
    let wearable_count = ctx
        .world
        .inventory
        .items
        .iter()
        .filter(|i| InventoryItem::is_wearable(i.item_type))
        .count();
    if wearable_count == 0 {
        return None;
    }

    let pos = ctx.portal.get_random_int() as usize % wearable_count;
    let mut i = 0;
    for item in &mut ctx.world.inventory.items {
        if InventoryItem::is_wearable(item.item_type) {
            if i == pos {
                return Some(i);
            }
            i += 1;
        }
    }

    None
}

fn engrave() -> Dialogue {
    Dialogue::new_free_text("Can you guess my secret?", Some(engrave_guess))
}

fn engrave_guess(ctx: &mut Ctx, response: &str) {
    if eq(response, SECRET) {
        ctx.start_dialogue(Dialogue::new_no_response(
            "That's correct! Here's your reward.\n\nObtained *Key* !",
            Some(get_item),
        ));
    } else {
        ctx.start_dialogue(Dialogue::new_free_text(
            "That's not it.\n:C\n\
             As consolation I can engrave your name onto the map.\nWhat's your name?",
            Some(engrave_name),
        ));
    }
}

fn engrave_name(ctx: &mut Ctx, response: &str) {
    let mut tiles: Vec<TileFlags, 64> = Vec::new();
    text_to_tiles(ctx, &mut tiles, response);
    text_to_tiles(ctx, &mut tiles, SECRET);
    ctx.vdp
        .set_plane_tiles(Plane::A, 45 * 64 + 10, &tiles[0..response.len()]);

    let img = &ctx.ui.inventory_text_img;
    ctx.vdp
        .set_tiles(img.start_tile, tileset::TILESETS[img.tiles_idx]);
    let cur = ctx.world.plane_window.current_scroll();
    ctx.vdp.set_h_scroll(0, &[-(cur.0 as i16), 0]);
    ctx.vdp
        .set_v_scroll(0, &[cur.1 as i16, image::SCREEN_V_SCROLL]);

    ctx.start_dialogue(Dialogue::new_no_response(
        "What a lovely name!\nI engraved it for your viewing pleasure.",
        None,
    ));
}

fn text_to_tiles(ctx: &Ctx, tiles: &mut Vec<TileFlags, 64>, text: &str) {
    let img = &ctx.ui.inventory_text_img;
    for chr in text.as_bytes().iter() {
        let tile = TileFlags::for_tile(
            img.start_tile + ui::CHAR_TILES_INDEXES[*chr as usize] as u16,
            img.palette,
        );
        info!("Converting {} -> {}", chr, tile.tile_index());
        tiles
            .push(tile)
            .unwrap_or_else(|_| panic!("tile vec too small"));
    }
}

fn eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.chars().zip(b.chars()).all(|(a, b)| a == b)
}

fn get_item(ctx: &mut Ctx, _: &str) {
    ctx.world.inventory.add(ItemType::Key);
}

impl Entity for Npc {
    fn hitbox(&self) -> Hitbox {
        let hb = Self::hitbox_for_type(self.npc_type);
        Hitbox {
            x: self.x + hb.x,
            y: self.y + hb.y,
            w: hb.w,
            h: hb.h,
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
