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

use heapless::Vec;
use megahx8::*;

use super::Enemy;
use super::Hitbox;
use super::Stats;
use crate::big_sprite::BigSprite;
use crate::data;
use crate::enemy;
use crate::enemy::EnemyImpl;
use crate::enemy::Status;
use crate::entity::*;
use crate::game::Ctx;
use crate::res::enemies::EnemyType;
use crate::res::sprites::explosion as ExplosionSprite;
use crate::res::sprites::fake_flame as FakeFlameSprite;
use crate::res::sprites::flame as FlameSprite;
use crate::resource_state::State;

pub(crate) fn new() -> EnemyImpl {
    EnemyImpl {
        stats,
        update_animation,
    }
}

fn stats(_enemy_type: EnemyType) -> Stats {
    Stats {
        speed: 16,
        health: 25,
        strength: 1,
        melee: true,
        shoots: false,
        sings: false,
        tracks: false,
        flies: false,
        hitbox: Hitbox {
            x: 20,
            y: 24,
            w: 88,
            h: 72,
        },
    }
}

fn update_animation(_enemy: &mut Enemy, _walking: bool) {}

pub fn should_render_sprite(enemy: &mut Enemy) -> bool {
    match enemy.status {
        Status::Dying {
            falling: _,
            cooldown,
            // Flash on and off in the  first half, then keep the flash o
            // for the second half of the death sequence.
        } => cooldown > enemy::BOSS_DEATH_COOLDOWN / 2 || (cooldown / 10) % 2 == 0,
        Status::KnockedBack {
            direction: _,
            cooldown,
        } => cooldown >= enemy::KNOCKBACK_COOLDOWN - 6,
        _ => false,
    }
}

/// Flames emitted by the boss.
struct Flame {
    fake: bool,
    moving: bool,
    sprite: BigSprite,
}

impl Flame {
    fn hitbox(&self) -> Hitbox {
        Hitbox {
            x: self.sprite.x as i16 + 2,
            y: self.sprite.y as i16 + 16,
            w: 28,
            h: 32,
        }
    }
}

fn new_flames(
    portal: &mut TargetPortal,
    res_state: &mut State,
    vdp: &mut TargetVdp,
) -> Vec<Flame, 8> {
    let mut flames = Vec::new();
    for i in 0..4 {
        let fake = portal.get_random_int() % 6 == 0;
        let mut sprite = if fake {
            FakeFlameSprite::new(res_state, vdp, /* keep_loaded= */ false)
        } else {
            FlameSprite::new(res_state, vdp, /* keep_loaded= */ false)
        };
        sprite.set_anim(FlameSprite::Anim::Idle as usize);
        sprite.x = 224 + i * 32;
        sprite.y = 240;
        flames
            .push(Flame {
                fake,
                moving: false,
                sprite,
            })
            .unwrap_or_else(|_| panic!("too many flames"));
    }
    flames
}

/// Boss related enemy state data.
pub struct BossState {
    /// Explosions for the boss death sequence.
    explosion_sprites: [BigSprite; 2],
    frame: u16,
    flames: Vec<Flame, 8>,
    pub drew_magic_picture: bool,
}

impl BossState {
    pub fn new(portal: &mut TargetPortal, res_state: &mut State, vdp: &mut TargetVdp) -> BossState {
        let mut explosion_sprites = [
            ExplosionSprite::new(res_state, vdp, /* keep_loaded= */ false),
            ExplosionSprite::new(res_state, vdp, /* keep_loaded= */ false),
        ];
        for sprite in &mut explosion_sprites {
            sprite.set_anim(ExplosionSprite::Anim::Explode as usize);
        }
        BossState {
            explosion_sprites,
            frame: 0,
            flames: new_flames(portal, res_state, vdp),
            drew_magic_picture: false,
        }
    }

    pub fn update(ctx: &mut Ctx) {
        if ctx.world.boss_state.is_none() {
            return;
        }
        let state = ctx.world.boss_state.as_mut().unwrap();

        let boss = ctx.world.enemies.iter_mut().find(|e| e.is_boss());
        if boss.is_none() {
            return;
        }
        let boss = boss.unwrap();

        for sprite in &mut state.explosion_sprites {
            sprite.update();
        }

        // Update explosion positions for the boss defeat sequence.
        if let Status::Dying {
            falling: _,
            cooldown,
        } = boss.status
        {
            let center = boss.hitbox().center();
            for (i, sprite) in state.explosion_sprites.iter_mut().enumerate() {
                // Start new explosions at random positions with a phase shift between the two sprites.
                let explosion_frame = cooldown as usize + 15 * i;
                if explosion_frame % 30 == 1 {
                    let (dx, dy) = data::EXPLOSION_OFFSETS[i][explosion_frame / 30];
                    sprite.set_position(center.0 - 8 + dx, center.1 - 8 + dy);
                    sprite.set_anim(ExplosionSprite::Anim::Explode as usize);
                }
            }
        }

        // Battle logic
        if !boss.is_alive() || ctx.players.iter().all(|p| !p.active || p.is_dead()) {
            return;
        }

        for i in 0..state.flames.len() {
            let flame = &mut state.flames[i];
            flame.sprite.update();

            if flame.moving {
                // Spread out the flames.
                flame.sprite.y += 2;
                if i == 0 {
                    flame.sprite.x -= 2;
                } else if i == 1 {
                    flame.sprite.x -= 1;
                } else if i == 2 {
                    flame.sprite.x += 1;
                } else {
                    flame.sprite.x += 2;
                }
            }

            if !flame.fake {
                let flame_hitbox = flame.hitbox();
                for player in &mut ctx.players {
                    if !player.is_active() {
                        continue;
                    }
                    if flame_hitbox.collides(&player.hitbox()) {
                        player.kill(/*falling=*/ false);
                    }
                }
            }
        }
        state.flames.retain(|f| f.sprite.y < 224 + 128);

        state.frame = state.frame.wrapping_add(1);
        if state.frame % 250 == 0 {
            // Shoot out current flames and spawn new ones in their place.
            for flame in &mut state.flames {
                flame.moving = true;
            }
            for flame in new_flames(&mut ctx.portal, &mut ctx.res_state, &mut ctx.vdp) {
                state
                    .flames
                    .push(flame)
                    .unwrap_or_else(|_| panic!("too many flames"));
            }
        }
    }

    pub fn render(&mut self, renderer: &mut TargetRenderer) {
        for sprite in &mut self.explosion_sprites {
            sprite.render(renderer);
        }
    }

    pub fn render_flames(&mut self, renderer: &mut TargetRenderer) {
        for flame in &mut self.flames {
            flame.sprite.render(renderer);
        }
    }
}
