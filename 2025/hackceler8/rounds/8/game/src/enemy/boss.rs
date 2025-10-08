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
use crate::map;
use crate::res::enemies::EnemyType;
use crate::res::sprites::explosion as ExplosionSprite;
use crate::res::sprites::swirl as SwirlSprite;
use crate::resource_state::State;
use crate::switch::SwitchProperties;
use crate::Player;
use crate::Switch;

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
            x: 12,
            y: 16,
            w: 104,
            h: 80,
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

const MAX_ROUNDS: u16 = 7;

/// Boss related enemy state data.
pub struct BossState {
    /// Explosions for the boss death sequence.
    explosion_sprites: [BigSprite; 2],
    swirl_sprite: BigSprite,
    frame: u16,
    round: u16,
    current_layout_idx: usize,
    rng_state: u32,
}

impl BossState {
    pub fn new(res_state: &mut State, vdp: &mut TargetVdp) -> BossState {
        let mut explosion_sprites = [
            ExplosionSprite::new(res_state, vdp, /* keep_loaded= */ false),
            ExplosionSprite::new(res_state, vdp, /* keep_loaded= */ false),
        ];
        for sprite in &mut explosion_sprites {
            sprite.set_anim(ExplosionSprite::Anim::Explode as usize);
        }
        let mut swirl_sprite = SwirlSprite::new(res_state, vdp, /* keep_loaded= */ false);
        swirl_sprite.set_anim(SwirlSprite::Anim::Off as usize);
        BossState {
            explosion_sprites,
            swirl_sprite,
            frame: 0,
            round: 0,
            current_layout_idx: 0,
            rng_state: 4,
        }
    }

    fn rand_num(&mut self, players: &[Player]) -> u32 {
        let inc = 1013904223;
        let mul = 1664525;
        for player in players {
            self.rng_state = self
                .rng_state
                .wrapping_mul(mul)
                .wrapping_add(player.x as u32);
            self.rng_state = self
                .rng_state
                .wrapping_mul(mul)
                .wrapping_add(player.y as u32);
        }
        self.rng_state = self.rng_state.wrapping_mul(mul).wrapping_add(inc);
        self.rng_state
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

        ctx.map_changed = false;
        for sprite in &mut state.explosion_sprites {
            sprite.update();
        }
        state.swirl_sprite.update();

        let center = boss.hitbox().center();
        // Update explosion positions for the boss defeat sequence.
        if let Status::Dying {
            falling: _,
            cooldown,
        } = boss.status
        {
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
        state
            .swirl_sprite
            .set_position(center.0 - 16, center.1 - 16);

        // Battle logic
        if !boss.is_alive() || ctx.players.iter().all(|p| !p.active || p.is_dead()) {
            return;
        }

        if ctx.world.map.is_none() {
            return;
        }
        let map = ctx.world.map.as_mut().unwrap();

        state.frame = state.frame.wrapping_add(1);
        if state.round >= MAX_ROUNDS {
            return;
        }

        if state.frame % 400 == 200 {
            state
                .swirl_sprite
                .set_anim(SwirlSprite::Anim::Swirl as usize);

            state.current_layout_idx = if state.round == MAX_ROUNDS - 1 {
                0
            } else {
                // Pick a random layout (making sure it's a different one).
                let mut idx =
                    state.rand_num(&ctx.players) as usize % enemy::data::BOSS_ATTR_LAYERS.len() - 1;
                if idx >= state.current_layout_idx {
                    idx += 1;
                }
                idx
            };
        }
        // Switch layout every 8s.
        if state.frame % 400 == 0 {
            state
                .swirl_sprite
                .set_anim(SwirlSprite::Anim::Stop as usize);

            if state.round == MAX_ROUNDS - 1 {
                for (i, pos) in [(28, 196), (292, 196), (36, 108), (284, 108)]
                    .iter()
                    .enumerate()
                {
                    let properties = SwitchProperties {
                        id: i as u16,
                        event_id: 2,
                    };
                    ctx.world
                        .switches
                        .push(Switch::new(
                            pos.0,
                            pos.1,
                            &properties,
                            /*completed=*/ false,
                            &mut ctx.res_state,
                            &mut ctx.vdp,
                        ))
                        .unwrap_or_else(|_| panic!("too many switches"));
                }
            }

            state.round += 1;
            map.attr_layer = map::Array2d::new(
                &enemy::data::BOSS_ATTR_LAYERS[state.current_layout_idx],
                map::WIDTH,
                map::HEIGHT,
            );
            map.gfx_layer = map::Array2d::new(
                &enemy::data::BOSS_GFX_LAYERS[state.current_layout_idx],
                map::WIDTH,
                map::HEIGHT,
            );
            map.load_to_vram(
                ctx.world.plane_window.vram_address(),
                &mut ctx.vdp,
                &mut ctx.res_state,
            );
            ctx.map_changed = true;
        }
    }

    pub fn render(&mut self, renderer: &mut TargetRenderer) {
        for sprite in &mut self.explosion_sprites {
            sprite.render(renderer);
        }
        self.swirl_sprite.render(renderer);
    }
}
