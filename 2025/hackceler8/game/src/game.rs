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

use crate::entity::*;
use crate::fader;
use crate::image;
use crate::image::Image;
use crate::player;
use crate::res::enemies::EnemyType;
use crate::res::images::game_over as GameOverImage;
use crate::res::maps::WorldType;
use crate::resource_state::State;
use crate::Dialogue;
use crate::Inventory;
use crate::InventoryScene;
use crate::Player;
use crate::World;
use crate::UI;

/// Debug const that spawns directly to a dungeon
pub const TEST_DUNGEON: Option<WorldType> = None; //Some(WorldType::FireTemple);

/// The amount of flags needed to unlock the boss temple.
pub const FLAGS_FOR_BOSS_TEMPLE: u16 = 2;

pub const MAX_PLAYERS: usize = 4;

const DEFAULT_PALETTE: [u16; 16] = [
    0x000, 0xFFF, 0xF00, 0x0F0, 0x00B, 0xFF0, 0xF0F, 0x0FF, 0x666, 0xBBB, 0x800, 0x080, 0x008,
    0x880, 0x808, 0x088,
];
const WIN_COLORS: [u16; 6] = [0x00F, 0x0FF, 0x0F0, 0xFF0, 0xF00, 0xF0F];

struct YouWin {
    frame: u16,
    current_palette: [u16; 16],
}

impl YouWin {
    pub(crate) fn new(vdp: &mut TargetVdp, captured_flags: u16) -> Self {
        vdp.wait_for_vblank();
        unsafe {
            vdp.reset_state();
        }
        vdp.set_plane_size(ScrollSize::Cell64, ScrollSize::Cell64);
        vdp.set_h_scroll(0, &[0, 0]);
        vdp.set_v_scroll(0, &[0, 0]);
        DEFAULT_FONT_1X1.load(vdp);

        vdp.set_palette(Palette::A, &DEFAULT_PALETTE);
        vdp.set_background(Palette::A, 0);

        DEFAULT_FONT_1X1.blit_text_to_plane(Plane::A, vdp, "Congratulations,", 12 * 64 + 11);
        DEFAULT_FONT_1X1.blit_text_to_plane(Plane::A, vdp, "you won the game!", 13 * 64 + 11);
        let mut msg: String<32> = String::new();
        let _ = write!(msg, "Total flags captured: {}", captured_flags);
        DEFAULT_FONT_1X1.blit_text_to_plane(Plane::A, vdp, &msg, 15 * 64 + 8);

        Self {
            frame: 0,
            current_palette: DEFAULT_PALETTE,
        }
    }

    pub(crate) fn update(&mut self) {
        self.frame += 1;
        for i in 1..16 {
            self.current_palette[i] =
                WIN_COLORS[(i + (self.frame as usize) / 10) % WIN_COLORS.len()];
        }
    }

    pub(crate) fn render(&self, vdp: &mut TargetVdp) {
        vdp.set_palette(Palette::A, &self.current_palette);
    }
}

struct GameOver {
    pub rendered: bool,
}

impl GameOver {
    pub(crate) fn new() -> GameOver {
        Self { rendered: false }
    }

    pub(crate) fn update(ctx: &mut Ctx) {
        for player_id in 0..ctx.players.len() {
            if let Some(input) = ctx.controller.controller_state(player_id) {
                if input.just_pressed(Button::A) {
                    ctx.reset();
                    ctx.world.clear();
                    break;
                }
            }
        }
    }

    pub(crate) fn render(&mut self, res_state: &mut State, vdp: &mut TargetVdp) {
        if self.rendered {
            return;
        }
        self.rendered = true;
        State::clear_screen(vdp, &[Plane::A, Plane::B]);
        res_state.reset();
        Image::draw(
            &GameOverImage::new(res_state, vdp, /* keep_loaded= */ false),
            11,
            9,
            vdp,
        );
        res_state.reset();
    }
}

#[derive(Copy, Clone)]
pub enum GameState {
    Playing,
    MapSwitch,
    Dialogue,
    Win,
}

pub type Ctx = Game<TargetControllers, TargetRenderer, TargetVdp>;

pub struct Game<C: Controllers, R: Renderer, V: Vdp> {
    pub vdp: V,
    pub res_state: State,
    renderer: R,
    pub controller: C,

    pub frame: u16,
    pub players: [Player; MAX_PLAYERS],
    pub world: World,
    /// Type of the new world to load. None if we should stay in the current world.
    pub new_world: Option<WorldType>,
    pub ui: UI,

    /// Map position in the overworld. Used to backup the position when entering a world.
    pub overworld_map_position: Option<(i16, i16)>,

    /// Stored player position in the overworld. Only stores the position of the player entering
    /// the world.
    pub overworld_player_position: Option<(i16, i16)>,
    /// Is the player exiting a world? is set to False by default.
    pub exiting_world: bool,

    /// Minibosses that were already defeated, represented as a bitmask.
    /// Only one miniboss for each type so we can use the type to keep
    /// track of them.
    pub defeated_minibosses: u16,

    /// Number of flags the player captured. Players can capture flags by defeating minibosses.
    pub captured_flags: u16,

    state: GameState,
    pub dialogue: Option<Dialogue>,
    game_over_scene: GameOver,
    win_scene: Option<YouWin>,
}

impl Game<TargetControllers, TargetRenderer, TargetVdp> {
    /// Creates a new [`Game`]
    ///
    /// # Panics
    /// When there are too many enemies, or other things go wrong.
    pub fn new(
        mut vdp: TargetVdp,
        renderer: TargetRenderer,
        controller: TargetControllers,
    ) -> Self {
        let mut res_state = crate::resource_state::init(&mut vdp);

        vdp.enable_interrupts(false, true, false);
        vdp.enable_display(true);
        vdp.set_plane_size(ScrollSize::Cell64, ScrollSize::Cell64);
        vdp.set_scroll_mode(HScrollMode::FullScroll, VScrollMode::FullScroll);
        vdp.set_h_scroll(0, &[0, 0]);
        vdp.set_v_scroll(0, &[0, image::SCREEN_V_SCROLL]);

        // Load sprites that must not be evicted first.
        Player::preload_persistent_sprites(&mut res_state, &mut vdp);
        UI::preload_persistent_sprites(&mut res_state, &mut vdp);

        let mut players = [
            Player::new(player::ID::P1, &mut res_state, &mut vdp),
            Player::new(player::ID::P2, &mut res_state, &mut vdp),
            Player::new(player::ID::P3, &mut res_state, &mut vdp),
            Player::new(player::ID::P4, &mut res_state, &mut vdp),
        ];

        let world = World::new(
            WorldType::Overworld,
            &mut res_state,
            &mut vdp,
            /*defeated_minibosses=*/ 0,
            /*captured_flags=*/ 0,
            &mut players,
            None,
        );

        let ui = UI::new(&mut res_state, &mut vdp);

        Game {
            vdp,
            res_state,
            renderer,
            controller,
            world,
            new_world: None,
            ui,
            exiting_world: false,
            defeated_minibosses: 0,
            captured_flags: 0,
            overworld_map_position: None,
            overworld_player_position: None,
            frame: 0,
            players,

            state: GameState::Playing,
            dialogue: None,
            game_over_scene: GameOver::new(),
            win_scene: None,
        }
    }

    /// Update the renderer
    ///
    /// # Panics
    /// When don't have a map set, or other weird things happen.
    pub fn update(&mut self) {
        let ctx = self;
        ctx.controller.update();

        match ctx.state {
            GameState::Playing => {
                InventoryScene::update(ctx);
                if matches!(ctx.world.inventory.scene, Some(_)) {
                    // Game is frozen while the inventory is open
                    return;
                }

                let player_count = ctx.players.len();

                for player_id in 0..player_count {
                    if let Some((x, y)) = Player::update(ctx, player_id) {
                        ctx.overworld_player_position = Some((x, y));
                        ctx.map_switch(World::get_entered_world(ctx));
                    }
                }

                if World::update(ctx) {
                    ctx.state = GameState::MapSwitch;
                }
                ctx.frame = ctx.frame.wrapping_add(1);

                // Win if the boss has been defeated.
                if ctx.defeated_minibosses & EnemyType::Boss as u16 != 0 {
                    ctx.state = GameState::Win;
                    ctx.win_scene = Some(YouWin::new(&mut ctx.vdp, ctx.captured_flags));
                } else if Player::reset_pressed(ctx) {
                    ctx.reset();
                }

                // Lose if all active players are dead.
                if ctx.players.iter().all(|p| !p.active || p.is_dead()) {
                    GameOver::update(ctx);
                }
            }
            GameState::MapSwitch => {
                InventoryScene::update(ctx);
                if matches!(ctx.world.inventory.scene, Some(_)) {
                    // Game is frozen while the inventory is open
                    return;
                }

                if let Some(new_world) = ctx.new_world {
                    fader::fade_in(ctx);

                    // Entering world -> Store current player positions.
                    let override_position = if ctx.exiting_world {
                        ctx.overworld_map_position.take()
                    } else {
                        ctx.overworld_map_position = Some(ctx.world.current_position);
                        None
                    };

                    // Unload prev world's tiles.
                    ctx.res_state.reset();

                    Inventory::clear(ctx);

                    ctx.world = World::new(
                        new_world,
                        &mut ctx.res_state,
                        &mut ctx.vdp,
                        ctx.defeated_minibosses,
                        ctx.captured_flags,
                        &mut ctx.players,
                        override_position,
                    );
                    ctx.ui.clear(&ctx.world);
                    ctx.new_world = None;
                    ctx.state = GameState::Playing;
                    ctx.game_over_scene.rendered = false;
                    if ctx.exiting_world {
                        // Go to the last position just before entering the dungeon.
                        if let Some((x, y)) = ctx.overworld_player_position.take() {
                            for player in ctx.players.iter_mut() {
                                player.set_position(x, y);
                            }
                        }
                    }
                    ctx.exiting_world = false;
                    fader::fade_out(ctx);
                } else if World::update_map_transition(ctx) {
                    ctx.state = GameState::Playing;
                }
            }
            GameState::Dialogue => {
                if let Some(response) = Dialogue::update(ctx) {
                    let mut on_finish = None;
                    if let Some(dialogue) = ctx.dialogue.take() {
                        on_finish = dialogue.on_finish;
                    }
                    ctx.state = GameState::Playing;
                    if let Some(on_finish) = on_finish {
                        on_finish(ctx, &response);
                    }
                    // Clear graphics unless on_finish started another dialogue.
                    if ctx.dialogue.is_none() {
                        Dialogue::clear(&mut ctx.vdp);
                    }
                }
            }
            GameState::Win => {
                ctx.win_scene.as_mut().map(YouWin::update);
            }
        }

        if let Some(test_dungeon) = TEST_DUNGEON {
            if let WorldType::Overworld = &ctx.world.world_type {
                ctx.map_switch(test_dungeon);
            }
        }
    }

    pub fn draw(&mut self) {
        if self.players.iter().all(|p| !p.active || p.is_dead()) {
            self.clear_sprites();
            self.game_over_scene
                .render(&mut self.res_state, &mut self.vdp);
        } else if self.win_scene.is_some() {
            self.clear_sprites();
            self.win_scene.as_ref().unwrap().render(&mut self.vdp);
        } else {
            self.ui.render(
                &self.players,
                &self.world,
                self.captured_flags,
                &mut self.vdp,
            );
            if let Some(dialogue) = &mut self.dialogue {
                dialogue.render(&self.ui, &mut self.vdp);
            } else {
                self.update_sprites();
            }
        }

        // vsync
        self.vdp.wait_for_vblank();
    }

    pub fn update_sprites(&mut self) {
        self.renderer.clear();

        for projectile in &mut self.world.projectiles {
            projectile.render(&mut self.renderer);
        }

        // Make sure sprites lower down the screen cover the ones higher up.
        let mut sort_stack: heapless::Vec<&mut dyn Entity, 80> = heapless::Vec::new();
        for enemy in &mut self.world.enemies {
            sort_stack
                .push(enemy)
                .unwrap_or_else(|_| panic!("sort stack too small"));
        }
        for npc in &mut self.world.npcs {
            sort_stack
                .push(npc)
                .unwrap_or_else(|_| panic!("sort stack too small"));
        }
        for item in &mut self.world.items {
            sort_stack
                .push(item)
                .unwrap_or_else(|_| panic!("sort stack too small"));
        }
        for player in &mut self.players {
            sort_stack
                .push(player)
                .unwrap_or_else(|_| panic!("sort stack too small"));
        }
        sort_stack.sort_unstable_by(|a, b| b.hitbox().center().1.cmp(&a.hitbox().center().1));
        for obj in sort_stack {
            obj.render(&mut self.renderer);
        }

        for door in &mut self.world.doors {
            door.render(&mut self.renderer);
        }
        for switch in &mut self.world.switches {
            switch.render(&mut self.renderer);
        }

        self.renderer.render(&mut self.vdp);
    }

    pub fn clear_sprites(&mut self) {
        self.renderer.clear();
        self.renderer.render(&mut self.vdp);
    }

    pub fn start_dialogue(&mut self, dialogue: Dialogue) {
        self.dialogue = Some(dialogue);
        self.state = GameState::Dialogue;
        self.update_sprites();
    }

    fn reset(&mut self) {
        // Return to overworld.
        self.exiting_world = true;
        self.map_switch(WorldType::Overworld);
    }

    /// Switch map to the given [`WorldType`]
    fn map_switch(&mut self, new_world: WorldType) {
        self.state = GameState::MapSwitch;
        self.new_world = Some(new_world);
    }
}

#[no_mangle]
pub extern "C" fn game_main() -> ! {
    let (vdp, renderer, controller) = init_hardware();
    let mut game = Game::new(vdp, renderer, controller);
    loop {
        game.update();
        game.draw();
    }
}
