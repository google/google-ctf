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

use crate::enemy::boss::BossDialogue;
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
pub const FLAGS_FOR_BOSS_TEMPLE: u16 = 4;

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

pub type Ctx = Game<TargetControllers, TargetRenderer, TargetVdp, TargetPortal>;

pub struct Game<C: Controllers, R: Renderer, V: Vdp, P: Portal> {
    pub vdp: V,
    pub res_state: State,
    pub portal: P,
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
    /// The ID of the NPC who's having the dialogue.
    pub dialogue_npc_id: Option<usize>,
    /// The ID if the player currently talking to an NPC.
    pub dialogue_player_id: Option<usize>,
    game_over_scene: GameOver,
    win_scene: Option<YouWin>,
    rng_state: u32,
    pub boss_dialogue: BossDialogue,
}

impl Game<TargetControllers, TargetRenderer, TargetVdp, TargetPortal> {
    /// Creates a new [`Game`]
    ///
    /// # Panics
    /// When there are too many enemies, or other things go wrong.
    pub fn new(
        mut vdp: TargetVdp,
        renderer: TargetRenderer,
        controller: TargetControllers,
        mut portal: TargetPortal,
    ) -> Self {
        vdp.enable_interrupts(false, true, false);
        vdp.enable_display(true);
        vdp.set_plane_size(ScrollSize::Cell64, ScrollSize::Cell64);
        vdp.set_scroll_mode(HScrollMode::FullScroll, VScrollMode::FullScroll);
        vdp.set_h_scroll(0, &[0, 0]);
        vdp.set_v_scroll(0, &[0, image::SCREEN_V_SCROLL]);

        wait_for_server_init(&mut vdp, &mut portal);

        let mut res_state = crate::resource_state::init(&mut vdp);

        let team_id = portal.get_team_id();

        // Load sprites that must not be evicted first.
        Player::preload_persistent_sprites(team_id, &mut res_state, &mut vdp);
        UI::preload_persistent_sprites(&mut res_state, &mut vdp);

        let mut players = [
            Player::new(player::ID::P1, team_id, &mut res_state, &mut vdp),
            Player::new(player::ID::P2, team_id, &mut res_state, &mut vdp),
            Player::new(player::ID::P3, team_id, &mut res_state, &mut vdp),
            Player::new(player::ID::P4, team_id, &mut res_state, &mut vdp),
        ];

        let (captured_flags, defeated_minibosses) = Self::load_game_challenges(&portal);
        Self::load_persistent_state(&portal);

        let world = World::new(
            WorldType::Overworld,
            &mut res_state,
            &mut vdp,
            defeated_minibosses,
            captured_flags,
            &mut players,
            None,
        );

        let ui = UI::new(&mut res_state, &mut vdp);

        Game {
            vdp,
            res_state,
            portal,
            renderer,
            controller,
            world,
            new_world: None,
            ui,
            exiting_world: false,
            defeated_minibosses,
            captured_flags,
            overworld_map_position: None,
            overworld_player_position: None,
            frame: 0,
            players,

            state: GameState::Playing,
            dialogue: None,
            dialogue_npc_id: None,
            dialogue_player_id: None,
            game_over_scene: GameOver::new(),
            win_scene: None,
            // Note: The starting state is different on the live console!
            rng_state: 0xF50FD4D,
            boss_dialogue: BossDialogue::new(),
        }
    }

    /// Update the renderer
    ///
    /// # Panics
    /// When don't have a map set, or other weird things happen.
    pub fn update(&mut self) {
        let ctx = self;

        ctx.block_if_server_paused();
        ctx.controller.update();

        if ctx.frame % 500 == 0 {
            // Save state every 10s.
            ctx.save_persistent_state();
        }

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
                    fader::fade(ctx, fader::FadeMode::Out, fader::FadeColor::White);
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
                    if matches!(new_world, WorldType::BossTemple)
                        && ctx.captured_flags < FLAGS_FOR_BOSS_TEMPLE
                    {
                        panic!("Insufficient flags to unlock boss");
                    }

                    fader::fade(ctx, fader::FadeMode::In, fader::FadeColor::Black);

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
                    ctx.draw(); // Make sure sprites are updated.
                    fader::fade(ctx, fader::FadeMode::Out, fader::FadeColor::Black);
                } else if World::update_map_transition(ctx) {
                    ctx.state = GameState::Playing;
                    ctx.world.shuffle_chests(&mut ctx.rng_state);
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

        if let Some(boss_state) = &mut self.world.boss_state {
            boss_state.render(&mut self.renderer);
        }

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

    /// Save and load completed challenges.
    pub fn save_game_challenges(&mut self) {
        self.portal.save_challenges(self.defeated_minibosses);
    }

    fn load_game_challenges(portal: &TargetPortal) -> (u16, u16) {
        let defeated_minibosses = portal.load_challenges();
        (
            World::get_flags_for_minibosses(defeated_minibosses),
            defeated_minibosses,
        )
    }

    /// Save and load other persistent state info.
    fn save_persistent_state(&mut self) {
        self.portal
            .save_to_persistent_storage(&[0x1234, 0x5678, 0x9ABC, 0xDEF0])
    }

    fn load_persistent_state(portal: &TargetPortal) {
        let mut save_buf = [0; 4];
        portal.load_from_persistent_storage(&mut save_buf);
        info!("Loaded data from storage: {:?}", save_buf);
    }

    /// Check if the server is paused and block + display a loading text until it gets unpaused.
    fn block_if_server_paused(&mut self) {
        if matches!(self.portal.get_server_state(), ServerState::Running) {
            return;
        }

        let text = "Match paused, please stand by...";
        UI::draw_text(text, 4, 14, &self.ui.inventory_text_img, &mut self.vdp);

        loop {
            self.vdp.wait_for_vblank();
            if matches!(self.portal.get_server_state(), ServerState::Running) {
                break;
            }
        }

        UI::clear_text(text, 4, 14, &mut self.vdp);

        // Reload challenges in case the server scoreboard changed.
        let (captured_flags, defeated_minibosses) = Self::load_game_challenges(&mut self.portal);
        self.captured_flags = captured_flags;
        self.defeated_minibosses = defeated_minibosses;
    }
}

/// Display a loading screen until the server has been initialized.
fn wait_for_server_init(vdp: &mut TargetVdp, portal: &mut TargetPortal) {
    if matches!(portal.get_server_state(), ServerState::Running) {
        return;
    }

    DEFAULT_FONT_1X1.load(vdp);
    vdp.set_palette(Palette::A, &DEFAULT_PALETTE);
    DEFAULT_FONT_1X1.blit_text_to_plane(Plane::A, vdp, "Waiting for server init...", 14 * 64 + 6);

    loop {
        vdp.wait_for_vblank();
        if matches!(portal.get_server_state(), ServerState::Running) {
            break;
        }
    }

    State::clear_screen(vdp, &[Plane::A, Plane::B]);
}

#[no_mangle]
pub extern "C" fn game_main() -> ! {
    let (vdp, renderer, controller, portal) = init_hardware();
    let mut game = Game::new(vdp, renderer, controller, portal);
    loop {
        game.update();
        game.draw();
    }
}
