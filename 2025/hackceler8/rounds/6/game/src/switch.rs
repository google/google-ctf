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
use crate::res::sprites::switch as SwitchSprite;
use crate::resource_state::State;

/// Possible events that can trigger when all switches on a map are pressed.
pub const EVENTS: &[fn(ctx: &mut Ctx)] = &[
    remove_enemies,           // 0
    open_doors,               // 1
    remove_hp_and_open_doors, // 2
    minigame,                 // 3
];

const WIDTH: i16 = 16;
const HEIGHT: i16 = 16;

/// When all switches on a map have a player standing on them an event is triggered.
pub struct Switch {
    pub x: i16,
    pub y: i16,
    sprite: BigSprite,
    pub id: u16,
    /// Index of the event that triggers when all map switches are pressed.
    /// Should be the same for switches on the same map.
    event_id: u16,
    progress: u16,
    frame_pressed: u16,
}

/// Properties parsed from the map.
pub struct SwitchProperties {
    /// A unique ID to idenfity the switch within the given world.
    pub id: u16,
    pub event_id: u16,
}

impl Switch {
    pub fn new(
        map_x: i16,
        map_y: i16,
        properties: &SwitchProperties,
        event_completed: bool,
        res_state: &mut State,
        vdp: &mut TargetVdp,
    ) -> Switch {
        let sprite_x = map_x + 128 - WIDTH / 2;
        let sprite_y = map_y + 128 - HEIGHT / 2;
        let mut sprite = SwitchSprite::new(res_state, vdp, /* keep_loaded= */ false);
        sprite.set_position(sprite_x, sprite_y);
        let mut switch = Switch {
            x: sprite_x,
            y: sprite_y,
            sprite,
            id: properties.id,
            event_id: properties.event_id,
            progress: 0,
            frame_pressed: 0,
        };
        switch.sprite.set_anim(if event_completed {
            SwitchSprite::Anim::On
        } else {
            SwitchSprite::Anim::Off
        } as usize);
        switch
    }

    /// Runs a tick.
    pub fn update(ctx: &mut Ctx) {
        let mut all_pressed = true;
        let mut lost = false;
        for s in 0..ctx.world.switches.len() {
            let switch = &mut ctx.world.switches[s];
            if ctx.world.switches_completed.is_set(switch.id) {
                // Switches for this map have already been triggered.
                return;
            }

            if switch.progress > 0 && switch.progress <= 5 {
                // Hurry, you only have 200 frames (4s)
                if ctx.frame.wrapping_sub(switch.frame_pressed) > 200 {
                    lost = true;
                    break;
                }
            }

            let hitbox = switch.hitbox();
            let mut pressed = false;
            for p in 0..ctx.players.len() {
                let player = &mut ctx.players[p];
                if player.is_active() && player.hitbox().collides(&hitbox) {
                    pressed = true
                }
            }

            switch.sprite.maybe_set_anim(if pressed {
                SwitchSprite::Anim::On as usize
            } else {
                SwitchSprite::Anim::Off as usize
            });

            if !pressed {
                all_pressed = false;
            }
        }

        if lost {
            lose(ctx);
        }

        // Trigger the switch event if all switches have been pressed.
        if all_pressed {
            let mut event_id = None;
            for switch in &mut ctx.world.switches {
                ctx.world.switches_completed.set(switch.id);
                event_id = Some(switch.event_id);
            }
            if let Some(event_id) = event_id {
                (EVENTS[event_id as usize])(ctx);
            }
        }
    }
}

impl Entity for Switch {
    fn hitbox(&self) -> Hitbox {
        Hitbox {
            x: self.x,
            y: self.y,
            w: WIDTH,
            h: HEIGHT,
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

/// Switch completion events.
fn remove_enemies(ctx: &mut Ctx) {
    for enemy in &mut ctx.world.enemies {
        enemy.kill(/*falling=*/ true);
    }
}

fn open_doors(ctx: &mut Ctx) {
    for door in &mut ctx.world.doors {
        door.open();
        ctx.world.doors_opened.set(door.id);
    }
}

fn remove_hp_and_open_doors(ctx: &mut Ctx) {
    for player in &mut ctx.players {
        if player.is_active() {
            player.on_hit((0, 0), 2);
        }
    }
    open_doors(ctx);
}

pub fn challenge_in_progress(ctx: &Ctx) -> bool {
    for switch in &ctx.world.switches {
        if switch.progress > 0 {
            return true;
        }
    }
    false
}

fn minigame(ctx: &mut Ctx) {
    // Check
    let mut lost = false;
    for s in 0..ctx.world.switches.len() {
        let switch = &mut ctx.world.switches[s];
        let hitbox = switch.hitbox();
        for p in 0..ctx.players.len() {
            if ctx.players[p].hitbox().collides(&hitbox)
                && !correct_player(p as u16, switch.id, switch.progress)
            {
                lost = true;
                break;
            }
        }
    }
    if lost {
        lose(ctx);
        return;
    }

    // Next state
    let mut won = false;
    for s in 0..ctx.world.switches.len() {
        let switch = &mut ctx.world.switches[s];
        let (dx, dy) = get_next_pos(switch.id, switch.progress);
        switch.progress += 1;

        if switch.progress == 6 {
            won = true;
            break;
        }

        switch.move_relative(dx * 40, dy * 40);
        switch.frame_pressed = ctx.frame;
        ctx.world.switches_completed.clear(switch.id);
    }
    if won {
        open_doors(ctx);
    }
}

fn lose(ctx: &mut Ctx) {
    for player in &mut ctx.players {
        player.kill(/*falling=*/ false);
    }
}

fn get_next_pos(id: u16, progress: u16) -> (i16, i16) {
    [
        (-1, 0),
        (2, -1),
        (-2, -1),
        (2, 1),
        (0, 1),
        (1, 2),
        (-1, 0),
        (1, -2),
        (-1, 0),
        (-1, 2),
        (0, -1),
        (-1, 0),
        (1, 2),
        (-2, -1),
        (2, -1),
        (0, -1),
        (0, 1),
        (0, 1),
        (1, 0),
        (-1, -2),
    ][id as usize * 5 + progress as usize]
}

fn correct_player(player_id: u16, switch_id: u16, progress: u16) -> bool {
    player_id
        == [
            1, 0, 1, 0, 3, 3, 2, 3, 0, 3, 0, 1, 0, 1, 3, 2, 2, 2, 3, 2, 2, 1, 1, 0,
        ][switch_id as usize * 6 + progress as usize]
}
