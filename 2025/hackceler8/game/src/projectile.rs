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
use resources::MapTileAttribute;

use crate::big_sprite::BigSprite;
use crate::entity::*;
use crate::game::Ctx;
use crate::get_map_mut;
use crate::map;
use crate::res::sprites::arrow::Anim;

pub const SPRITE_SIZE: i16 = 16;
pub const HITBOX_SIZE: i16 = 4;
pub const SPEED_PER_FRAME: i16 = 2;

pub struct Projectile {
    pub shooter_id: u16,
    pub x: i16,
    pub y: i16,
    damage: u16,
    trajectory: Trajectory,
    sprite: BigSprite,
    status: Status,
}

#[derive(PartialEq)]
enum Status {
    Flying,
    Dead,
}

impl Projectile {
    pub fn new(
        shooter_id: u16,
        x: i16,
        y: i16,
        dx: i16,
        dy: i16,
        damage: u16,
        mut sprite: BigSprite,
    ) -> Projectile {
        let flip_h = dx < 0;
        let flip_v = dy < 0;
        let anim = if dx.abs() / 2 < dy.abs() && dy.abs() / 2 < dx.abs() {
            Anim::Diag
        } else if dx.abs() > dy.abs() {
            Anim::Right
        } else {
            Anim::Down
        };
        sprite.set_anim(anim as usize);
        sprite.flip_h = flip_h;
        sprite.flip_v = flip_v;

        Projectile {
            shooter_id,
            x,
            y,
            damage,
            trajectory: Trajectory::new(x, y, dx, dy),
            sprite,
            status: Status::Flying,
        }
    }

    pub fn update(ctx: &mut Ctx, projectile_id: usize) {
        let projectile = &mut ctx.world.projectiles[projectile_id];
        let map = get_map_mut!(ctx);

        match projectile.status {
            Status::Dead => {}
            Status::Flying => {
                let (new_x, new_y) = projectile.trajectory.update();
                let push_dir = ((new_x - projectile.x) * 30, (new_y - projectile.y) * 30);
                projectile.set_position(new_x, new_y);

                for player in &mut ctx.players {
                    if !player.is_active() {
                        continue;
                    }
                    if projectile.hitbox().collides(&player.hitbox()) {
                        player.on_hit(push_dir, projectile.damage);
                        projectile.status = Status::Dead;
                        break;
                    }
                }
                if projectile.status != Status::Dead {
                    if map
                        .get_hit_tiles(&projectile.hitbox())
                        .touches_tile(MapTileAttribute::Wall)
                        || map::off_screen(projectile.x, projectile.y)
                    {
                        projectile.status = Status::Dead;
                    }
                }
            }
        }
    }

    /// Returns true if the projectile should be unloaded from memory.
    pub fn should_unload(&self) -> bool {
        matches!(self.status, Status::Dead)
    }

    pub fn reset_trajectory(&mut self) {
        self.trajectory.reset(self.x, self.y);
    }
}

// Info about the direction the projectile is going on and current progress.
struct Trajectory {
    start_x: i16,
    start_y: i16,
    // Total distance to travel in |frames_to_dest| frames.
    dx: i16,
    dy: i16,
    frames_to_dest: i16,
    curr_frame: i16,
}

impl Trajectory {
    fn new(x: i16, y: i16, dx: i16, dy: i16) -> Self {
        let frames_to_dest = dx.abs().max(dy.abs()) / SPEED_PER_FRAME;
        Self {
            start_x: x,
            start_y: y,
            dx,
            dy,
            frames_to_dest,
            curr_frame: 0,
        }
    }

    // Returns the position for the next frame.
    fn update(&mut self) -> (i16, i16) {
        self.curr_frame += 1;
        (
            self.start_x + self.dx * self.curr_frame / self.frames_to_dest,
            self.start_y + self.dy * self.curr_frame / self.frames_to_dest,
        )
    }

    /// Resets the trajectory to start from the given coordinates.
    fn reset(&mut self, x: i16, y: i16) {
        self.start_x = x;
        self.start_y = y;
        self.curr_frame = 0;
    }
}

impl Entity for Projectile {
    fn hitbox(&self) -> Hitbox {
        Hitbox {
            x: self.x + SPRITE_SIZE / 2 - HITBOX_SIZE / 2,
            y: self.y + SPRITE_SIZE / 2 - HITBOX_SIZE / 2,
            w: HITBOX_SIZE,
            h: HITBOX_SIZE,
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
