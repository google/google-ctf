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
use crate::game::Ctx;
use crate::image::Image;
use crate::res::images::stage_select_bg as BgImage;
use crate::res::maps::MapType;
use crate::res::sprites::level_display as LevelDisplaySprite;
use crate::res::sprites::selection as SelectionSprite;
use crate::resource_state::State;
use crate::PlayerType;

/// The dimensions of the level selection grid.
const GRID_W: u16 = 3;
const GRID_H: u16 = 3;

pub struct StageSelect {
    boss_unlocked: bool,
    first_render: bool,
    /// The currently selected level's (x, y) grid coordinates.
    selection: (u16, u16),
    selection_sprites: [Option<BigSprite>; 4],
    level_display_sprite: Option<BigSprite>,
}

impl StageSelect {
    pub fn with_boss_unlock_status(boss_unlocked: bool) -> StageSelect {
        let selection_sprites = [const { None }; 4];
        Self {
            boss_unlocked,
            first_render: true,
            selection: (0, 0),
            selection_sprites,
            level_display_sprite: None,
        }
    }

    pub fn update(ctx: &mut Ctx) {
        if ctx.stage_select_scene.is_none() {
            return;
        }
        let scene = ctx.stage_select_scene.as_mut().unwrap();

        if let Some(input) = ctx.controller.controller_state(0) {
            // Attested reset: start a fresh timed run from a cleared
            // game state. Chorded so it cannot be hit by accident --
            // Mode+Start on a 6-button pad, A+C+Start on a 3-button one.
            let reset_held = input.is_pressed(Button::A) && input.is_pressed(Button::C);
            if reset_held && input.just_pressed(Button::Start) {
                ctx.portal.request_console_reset();
                return;
            }

            if scene.is_selecting_player() {
                if input.just_pressed(Button::A) || input.just_pressed(Button::Start) {
                    if let Some(map) = map_for_selection(scene.selection, scene.boss_unlocked) {
                        let player_type = scene.selected_player_type();
                        ctx.load_map(map, player_type);
                        return;
                    }
                } else if input.just_pressed(Button::Left) || input.just_pressed(Button::Right) {
                    // Toggle between player types.
                    if let Some(s) = &mut scene.level_display_sprite {
                        s.set_animation(if s.current_animation()
                            == LevelDisplaySprite::Anim::Shooter as usize
                        {
                            LevelDisplaySprite::Anim::Melee
                        } else {
                            LevelDisplaySprite::Anim::Shooter
                        } as usize);
                    }
                }
            } else {
                let mut level_changed = true;
                if input.just_pressed(Button::A) || input.just_pressed(Button::Start) {
                    if map_for_selection(scene.selection, scene.boss_unlocked).is_some() {
                        // Level selected - Select player type next.
                        if let Some(s) = &mut scene.level_display_sprite {
                            s.set_animation(LevelDisplaySprite::Anim::Shooter as usize);
                        }
                    }
                } else if input.just_pressed(Button::Left) && scene.selection.0 > 0 {
                    scene.selection.0 -= 1;
                } else if input.just_pressed(Button::Right) && scene.selection.0 + 1 < GRID_W {
                    scene.selection.0 += 1;
                } else if input.just_pressed(Button::Up) && scene.selection.1 > 0 {
                    scene.selection.1 -= 1
                } else if input.just_pressed(Button::Down) && scene.selection.1 + 1 < GRID_H {
                    scene.selection.1 += 1
                } else {
                    level_changed = false;
                }

                if level_changed {
                    // Level changed - update display screen.
                    if scene.boss_unlocked {
                        // Display should always show the boss screen if it's unlocked.
                        return;
                    }
                    if !scene.is_selecting_player() {
                        if let Some(s) = &mut scene.level_display_sprite {
                            let map = map_for_selection(scene.selection, scene.boss_unlocked);
                            if let Some(map) = map {
                                s.set_animation(match map {
                                    MapType::Arctic => LevelDisplaySprite::Anim::Water,
                                    MapType::Forest => LevelDisplaySprite::Anim::Forest,
                                    MapType::Volcano => LevelDisplaySprite::Anim::Fire,
                                    MapType::Spaceship => LevelDisplaySprite::Anim::Sky,
                                    MapType::BossStage => LevelDisplaySprite::Anim::Boss,
                                } as usize);
                            }
                        }
                    }
                }
            }
        }
        for i in 0..scene.selection_sprites.len() {
            if let Some(s) = &mut scene.selection_sprites[i] {
                (s.x, s.y) = selection_pos(i, scene.selection);
                s.update();
            }
        }
        if let Some(s) = &mut scene.level_display_sprite {
            s.update();
        }
    }

    pub fn render(
        &mut self,
        res_state: &mut State,
        vdp: &mut TargetVdp,
        renderer: &mut TargetRenderer,
    ) {
        if self.first_render {
            self.first_render = false;
            State::clear_screen(vdp, &[Plane::A, Plane::B]);
            res_state.reset();
            vdp.set_h_scroll(0, &[0, 0]);
            vdp.set_v_scroll(0, &[0, 0]);

            // Bg
            Image::draw(
                &BgImage::new(res_state, vdp, /* keep_loaded= */ false),
                7,
                1,
                vdp,
                Plane::B,
            );

            // Level display
            let mut s = LevelDisplaySprite::new(
                res_state, vdp, /* singleton= */ true, /* keep_loaded= */ false,
            );
            s.set_animation(if self.boss_unlocked {
                LevelDisplaySprite::Anim::Boss
            } else {
                LevelDisplaySprite::Anim::Empty
            } as usize);
            s.x = 232;
            s.y = 184;
            s.priority = true;
            self.level_display_sprite = Some(s);

            // Selection sprites
            for i in 0..self.selection_sprites.len() {
                let mut s = SelectionSprite::new(
                    res_state, vdp, /* singleton= */ false, /* keep_loaded= */ false,
                );
                s.set_animation(SelectionSprite::Anim::Flash as usize);
                s.flip_h = i % 2 == 1;
                s.flip_v = i / 2 == 1;
                s.priority = true;
                (s.x, s.y) = selection_pos(i, self.selection);
                self.selection_sprites[i] = Some(s);
            }
        }

        renderer.clear();
        if !self.is_selecting_player() {
            for s in &mut self.selection_sprites {
                if let Some(s) = s {
                    s.render(res_state, vdp, renderer);
                }
            }
        }
        if let Some(s) = &mut self.level_display_sprite {
            s.render(res_state, vdp, renderer);
        }
        renderer.render(vdp);
    }

    /// Whether we're currently in the player selection phase (after a level has been selected).
    fn is_selecting_player(&self) -> bool {
        if let Some(s) = &self.level_display_sprite {
            let anim = s.current_animation();
            return anim == LevelDisplaySprite::Anim::Shooter as usize
                || anim == LevelDisplaySprite::Anim::Melee as usize;
        }
        false
    }

    fn selected_player_type(&self) -> PlayerType {
        if let Some(s) = &self.level_display_sprite {
            if s.current_animation() == LevelDisplaySprite::Anim::Melee as usize {
                return PlayerType::Melee;
            }
        }
        PlayerType::Shooter
    }
}

/// Computes the pixel coordinates of the selection sprite with the given
/// ID based on the grid coordinates.
fn selection_pos(idx: usize, grid_pos: (u16, u16)) -> (u16, u16) {
    let (mut x, mut y) = (64, 16);
    for x_iter in 0..grid_pos.0 {
        x += cell_dimensions((x_iter, 0)).0 + 22;
    }
    for y_iter in 0..grid_pos.1 {
        y += cell_dimensions((0, y_iter)).1 + 22;
    }

    let (w, h) = cell_dimensions(grid_pos);

    (
        x + (idx as u16 % 2) * w + 128,
        y + (idx as u16 / 2) * h + 128,
    )
}

/// The width/height of a button with a given position in the grid.
fn cell_dimensions(grid_pos: (u16, u16)) -> (u16, u16) {
    // Buttons in the middle are longer.
    (
        if grid_pos.0 == GRID_W / 2 { 76 } else { 24 },
        if grid_pos.1 == GRID_H / 2 { 76 } else { 24 },
    )
}

/// The map accessed by selecting the level at the given grid position.
fn map_for_selection(grid_pos: (u16, u16), boss_unlocked: bool) -> Option<MapType> {
    match grid_pos {
        (1, 0) => Some(MapType::Arctic),
        (0, 1) => Some(MapType::Forest),
        (2, 1) => Some(MapType::Spaceship),
        (1, 2) => Some(MapType::Volcano),
        (1, 1) => {
            if boss_unlocked {
                Some(MapType::BossStage)
            } else {
                None
            }
        }
        _ => None,
    }
}
