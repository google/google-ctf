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
use resources::MapTileAttribute;

use crate::big_sprite::BigSprite;
use crate::entity::*;
use crate::game::Ctx;
use crate::get_map_data_mut;
use crate::map;
use crate::res::sprites::arrow::Anim;
use crate::resource_state::State;
use crate::Direction;

pub struct Projectile {
    pub x: i16,
    pub y: i16,
    damage: u16,
    trajectory: Trajectory,
    pub sprite: BigSprite,
    status: Status,
    pub is_player: bool,
}

#[derive(PartialEq)]
enum Status {
    Flying,
    Explosion,
    Dead,
}

impl Projectile {
    pub fn new(
        x: i16,
        y: i16,
        dx: i16,
        dy: i16,
        speed: i16,
        damage: u16,
        mut sprite: BigSprite,
        is_player: bool,
    ) -> Projectile {
        let flip_h = dx > 0;
        let flip_v = dy < 0;
        let anim = if dx.abs() / 2 < dy.abs() && dy.abs() / 2 < dx.abs() {
            Anim::Diag
        } else if dx.abs() > dy.abs() {
            Anim::Right
        } else {
            Anim::Down
        };
        sprite.set_animation(anim as usize);
        sprite.flip_h = flip_h;
        sprite.flip_v = flip_v;

        Projectile {
            x,
            y,
            damage,
            trajectory: Trajectory::new(x, y, dx, dy, speed),
            sprite,
            status: Status::Flying,
            is_player,
        }
    }

    fn explode(&mut self) {
        self.status = Status::Explosion;
        self.sprite.set_animation(Anim::Explosion as usize);
    }

    pub fn update(ctx: &mut Ctx, projectile_id: usize) {
        let projectile = &mut ctx.map.projectiles[projectile_id];
        let map = get_map_data_mut!(ctx);

        projectile.sprite.update();

        match projectile.status {
            Status::Dead => {}
            Status::Explosion => {
                if projectile.sprite.is_animation_finished() {
                    projectile.status = Status::Dead;
                }
            }
            Status::Flying => {
                let (new_x, new_y) = projectile.trajectory.update();
                let dx = new_x - projectile.x;
                let dy = new_y - projectile.y;
                let mut hitbox = projectile.hitbox();
                if dx == 0 || dy == 0 {
                    hitbox = hitbox.extend_by(dx, dy)
                };

                projectile.set_position(new_x, new_y);

                if projectile.is_player {
                    for enemy in &mut ctx.map.enemies {
                        if !enemy.is_alive() {
                            continue;
                        }
                        if hitbox.collides(&enemy.hitbox()) {
                            enemy.on_hit(projectile.damage);
                            projectile.explode();
                            break;
                        }
                    }
                    if projectile.status == Status::Flying {
                        for s in 0..ctx.map.switches.len() {
                            let id = ctx.map.switches[s].id;
                            if ctx.map.switches_completed.is_set(id) || ctx.map.switches[s].pending
                            {
                                continue;
                            }
                            if hitbox.collides(&ctx.map.switches[s].hitbox()) {
                                ctx.map.switches[s].pending = true;
                                projectile.explode();
                                break;
                            }
                        }
                    }
                } else {
                    if ctx.player.is_active() && hitbox.collides(&ctx.player.hitbox()) {
                        let dir = if dx < 0 {
                            Direction::Left
                        } else {
                            Direction::Right
                        };
                        ctx.player.on_hit(dir, projectile.damage);
                        projectile.explode();
                    }
                }
                if projectile.status == Status::Flying {
                    if map::is_off_screen(projectile.x, projectile.y) {
                        projectile.status = Status::Dead;
                    } else if ctx
                        .map
                        .doors
                        .iter()
                        .any(|door| !door.open && door.hitbox().collides(&hitbox))
                        || map
                            .get_hit_tiles(&hitbox, ctx.map.scroll_offset)
                            .touches_tile(MapTileAttribute::Wall)
                    {
                        projectile.explode();
                    }
                }
            }
        }
    }

    /// Move the projectile as part of map scrolling, making sure
    /// to keep it on the same trajectory as before.
    pub fn scroll(&mut self, dx: i16, dy: i16) {
        self.move_relative(dx, dy);
        self.trajectory.start_x += dx;
        self.trajectory.start_y += dy;
    }

    /// Returns true if the projectile should be unloaded from memory.
    pub fn should_unload(&self) -> bool {
        matches!(self.status, Status::Dead)
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
    fn new(x: i16, y: i16, dx: i16, dy: i16, speed: i16) -> Self {
        let frames_to_dest = dx.abs().max(dy.abs()) / speed;
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
}

impl Entity for Projectile {
    fn hitbox(&self) -> Hitbox {
        let (tile_w, tile_h) = self.sprite.tile_dimensions();
        let sprite_w = tile_w as i16 * 8;
        let sprite_h = tile_h as i16 * 8;
        let hitbox_w = (sprite_w / 2).max(4);
        let hitbox_h = (sprite_h / 2).max(4);
        Hitbox {
            x: self.x + sprite_w / 2 - hitbox_w / 2,
            y: self.y + sprite_h / 2 - hitbox_h / 2,
            w: hitbox_w,
            h: hitbox_h,
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
