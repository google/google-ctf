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

use heapless::String;
use megahx8::*;

use crate::big_sprite::BigSprite;
use crate::enemy::boss;
use crate::entity::*;
use crate::game::Ctx;
use crate::res::items::ItemType;
use crate::res::npcs;
use crate::res::npcs::NpcType;
use crate::res::sprites::racoon_npc as Sprite;
use crate::resource_state::State;
use crate::Dialogue;

pub const DIALOGUES: &[fn() -> Dialogue] = &[
    example_dialogue, // 0
    bark_bark,        // 1
    paint,            // 2
    boss::computer,   // 3
];

// Note: The secret is different on the live console!
const SECRET: &str = "TEST_SECRET_1234";

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
            NpcType::ComputerNpc => Hitbox {
                x: 2,
                y: 12,
                w: 20,
                h: 10,
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

fn paint() -> Dialogue {
    Dialogue::new_free_text("Can you guess my secret?", Some(paint_guess))
}

fn paint_guess(ctx: &mut Ctx, response: &str) {
    if eq(response, SECRET) {
        ctx.start_dialogue(Dialogue::new_no_response(
            "That's correct! Here's your reward.\n\nObtained *Key* !",
            Some(get_item),
        ));
    } else {
        ctx.start_dialogue(Dialogue::new_free_text_restricted_charset(
            "That's not it.\nAs consolation I can paint 1024 bytes from the my picture for you. \
             What should the starting address be?",
            "0123456789ABCDEF",
            Some(paint_tiles),
        ));
    }
}

fn paint_tiles(ctx: &mut Ctx, response: &str) {
    let address = u32::from_str_radix(response, 16);
    if !address.is_ok() {
        ctx.start_dialogue(Dialogue::new_no_response("That's not an integer :C", None));
        return;
    }
    let address = address.unwrap();
    if address % 2 != 0 {
        ctx.start_dialogue(Dialogue::new_no_response(
            "That's not word-aligned :C",
            None,
        ));
    }

    let range_start = 0x100000;
    let range_end = 0x160000;
    if address < range_start || address >= range_end - 1024 {
        let mut text: String<100> = String::new();
        let _ = write!(
            text,
            "That's not in the valid tileset range, it should between 0x{:x} - 0x{:x}.",
            range_start, range_end,
        );
        ctx.start_dialogue(Dialogue::new_no_response(&text, None));
        return;
    }

    if range_contains_secret(address) {
        ctx.start_dialogue(Dialogue::new_no_response(
            "I can't paint that, those 1024 bytes might contain a secret!",
            None,
        ));
        return;
    }

    ctx.vdp
        .set_tiles_raw(ctx.res_state.next_tile_pos, address, 1024);
    for i in 0..32 {
        let tiles = &mut [TileFlags::new()];
        tiles[0] =
            *TileFlags::for_tile(ctx.res_state.next_tile_pos + i, Palette::C).set_priority(true);
        ctx.vdp.set_plane_tiles(Plane::B, 46 * 64 + 1 + i, tiles);
    }

    ctx.start_dialogue(Dialogue::new_no_response(
        "Alright, I painted it onto the screen for your viewing pleasure.",
        None,
    ));
}

fn range_contains_secret(address_start: u32) -> bool {
    let address_end = address_start + 1024;
    let mut secret_start = 0xfdf00;
    for _ in 0..22 {
        secret_start += 0x4440;
        let secret_end = secret_start + 0x200;
        if address_end > secret_start && address_start < secret_end {
            return true;
        }
    }
    false
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
