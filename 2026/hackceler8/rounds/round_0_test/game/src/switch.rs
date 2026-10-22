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
use crate::res::sprites::switch as SwitchSprite;
use crate::resource_state::State;

/// Possible events that can trigger when a switch is pressed.
pub const EVENTS: &[fn(ctx: &mut Ctx)] = &[
    remove_enemies, // 0
    open_door_0,    // 1
];

const WIDTH: i16 = 16;
const HEIGHT: i16 = 16;

/// When the player stands on a switch, its event is triggered.
pub struct Switch {
    pub x: i16,
    pub y: i16,
    sprite: BigSprite,
    pub id: u16,
    /// Index of the event that triggers when this switch is pressed.
    event_id: u16,
    /// True if the switch has been triggered but the event has not yet been processed.
    pub pending: bool,
}

/// Properties parsed from the map.
pub struct SwitchProperties {
    /// A unique ID to idenfity the switch within the given map.
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
        let mut sprite = SwitchSprite::new(
            res_state, vdp, /* singleton= */ false, /* keep_loaded= */ false,
        );
        sprite.set_position(sprite_x, sprite_y);
        let mut switch = Switch {
            x: sprite_x,
            y: sprite_y,
            sprite,
            id: properties.id,
            event_id: properties.event_id,
            pending: false,
        };
        switch.sprite.set_animation(if event_completed {
            SwitchSprite::Anim::On
        } else {
            SwitchSprite::Anim::Off
        } as usize);
        switch
    }

    /// Runs a tick.
    pub fn update(ctx: &mut Ctx) {
        for s in 0..ctx.map.switches.len() {
            if ctx.map.switches[s].pending {
                ctx.map.switches[s].pending = false;
                let id = ctx.map.switches[s].id;
                ctx.map.switches_completed.set(id);
                let event_id = ctx.map.switches[s].event_id;
                (EVENTS[event_id as usize])(ctx);
                ctx.map.switches[s]
                    .sprite
                    .maybe_set_animation(SwitchSprite::Anim::On as usize);
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

/// Switch completion events.
fn remove_enemies(ctx: &mut Ctx) {
    for enemy in &mut ctx.map.enemies {
        enemy.kill();
    }
}

fn open_door_0(ctx: &mut Ctx) {
    for door in &mut ctx.map.doors {
        if door.id == 0 {
            door.unlock();
            door.open();
            ctx.map.doors_unlocked.set(door.id);
            ctx.map.doors_locked.clear(door.id);
        }
    }
}
