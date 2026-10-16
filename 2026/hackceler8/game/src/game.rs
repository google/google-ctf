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

use core::fmt::Write;

use heapless::String;
use megahx8::*;

use crate::entity::*;
use crate::fader;
use crate::image::Image;
use crate::placement::emplace;
use crate::player;
use crate::res::images::game_over as GameOverImage;
use crate::res::maps;
use crate::res::maps::MapType;
use crate::res::palettes;
use crate::resource_state::State;
use crate::Dialogue;
use crate::Inventory;
use crate::InventoryScene;
use crate::Map;
use crate::Player;
use crate::PlayerType;
use crate::StageSelect;
use crate::MAP_COUNT;
use crate::UI;

/// The amount of flags needed to unlock the boss.
pub const FLAGS_FOR_BOSS: u16 = 1;

const DEFAULT_PALETTE: [u16; 16] = [
    0x000, 0xFFF, 0xF00, 0x0F0, 0x00B, 0xFF0, 0xF0F, 0x0FF, 0x666, 0xBBB, 0x800, 0x080, 0x008,
    0x880, 0x808, 0x088,
];
const WIN_COLORS: [u16; 6] = [0x00F, 0x0FF, 0x0F0, 0xFF0, 0xF00, 0xF0F];

struct YouWin {
    cycles: u32,
    rendered: bool,
    frame: u16,
    current_palette: [u16; 16],
}

impl YouWin {
    pub(crate) fn new(cycles: u32) -> Self {
        Self {
            cycles,
            rendered: false,
            frame: 0,
            current_palette: DEFAULT_PALETTE,
        }
    }

    pub(crate) fn update(ctx: &mut Ctx) {
        if let Some(input) = ctx.controller.controller_state(0) {
            if input.just_pressed(Button::A) || input.just_pressed(Button::Start) {
                ctx.switch_to_stage_select();
                return;
            }
        }
        if let Some(scene) = ctx.win_scene.as_mut() {
            scene.frame += 1;
            for i in 1..16 {
                scene.current_palette[i] =
                    WIN_COLORS[(i + (scene.frame as usize) / 10) % WIN_COLORS.len()];
            }
        }
    }

    pub(crate) fn render(&mut self, ui: &UI, res_state: &mut State, vdp: &mut TargetVdp) {
        if !self.rendered {
            self.rendered = true;
            State::clear_screen(vdp, &[Plane::A, Plane::B]);
            res_state.reset();
            vdp.set_h_scroll(0, &[0, 0]);
            vdp.set_v_scroll(0, &[0, 0]);

            UI::draw_text("Congrats!", 15, 11, &ui.text_img, vdp, Plane::B);
            let mut msg: String<40> = String::new();
            let _ = write!(msg, "You beat the boss in {} cycles!", self.cycles);
            let col = (40u16.saturating_sub(msg.len() as u16)) / 2;
            UI::draw_text(&msg, col, 13, &ui.text_img, vdp, Plane::B);
            UI::draw_text(
                "Press A or START to continue",
                6,
                16,
                &ui.text_img,
                vdp,
                Plane::B,
            );
        }
        vdp.set_palette(Palette::B, &self.current_palette);
    }
}

struct GameOver {
    rendered: bool,
}

impl GameOver {
    pub(crate) fn new() -> GameOver {
        Self { rendered: false }
    }

    pub(crate) fn update(ctx: &mut Ctx) {
        if let Some(input) = ctx.controller.controller_state(0) {
            if input.just_pressed(Button::A) || input.just_pressed(Button::Start) {
                ctx.switch_to_stage_select();
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
            Plane::B,
        );
    }
}

#[derive(Copy, Clone)]
pub enum GameState {
    StageSelect,
    Playing,
    Paused,
    Dialogue,
    GameOver,
    Win,
}

pub type Ctx = Game<TargetControllers, TargetRenderer, TargetVdp, TargetPortal>;

pub struct Game<C: Controllers, R: Renderer, V: Vdp, P: Portal> {
    pub vdp: V,
    pub res_state: State,
    pub portal: P,
    renderer: R,
    pub controller: C,

    /// Frames used for calculating the flag score. Incremented on every in-game frame.
    pub score_frame: u32,

    pub player: Player,
    pub map: Map,
    pub ui: UI,

    /// Minibosses that were already defeated, represented as a bitmask.
    /// Only one miniboss for each type so we can use the type to keep
    /// track of them.
    pub defeated_minibosses: u32,

    /// Number of flags the player captured. The player can capture flags by defeating minibosses.
    pub captured_flags: u16,

    state: GameState,
    pub dialogue: Option<Dialogue>,
    pub stage_select_scene: Option<StageSelect>,
    pub inventory_scene: InventoryScene,
    game_over_scene: Option<GameOver>,
    win_scene: Option<YouWin>,
}

impl Game<TargetControllers, TargetRenderer, TargetVdp, TargetPortal> {
    /// Creates a new [`Game`]
    pub fn new(
        vdp: TargetVdp,
        renderer: TargetRenderer,
        controller: TargetControllers,
        portal: TargetPortal,
    ) -> Self {
        let mut game = core::mem::MaybeUninit::<Self>::uninit();
        // SAFETY: `emplace` fully initialises the `Game` behind the pointer.
        unsafe {
            Self::emplace(game.as_mut_ptr(), vdp, renderer, controller, portal);
            game.assume_init()
        }
    }

    /// Initialise a [`Game`] directly into `this` without building a by-value
    /// temporary (see [`crate::placement`]). The m68k entry point uses this so
    /// the ~10KB `Game` is never copied through the stack on construction.
    ///
    /// # Safety
    /// `this` must point to writable, aligned, uninitialised memory for a `Game`.
    pub unsafe fn emplace(
        this: *mut Self,
        mut vdp: TargetVdp,
        renderer: TargetRenderer,
        controller: TargetControllers,
        mut portal: TargetPortal,
    ) {
        vdp.enable_interrupts(false, true, false);
        vdp.enable_display(true);
        vdp.set_plane_size(ScrollSize::Cell64, ScrollSize::Cell64);
        vdp.set_scroll_mode(HScrollMode::FullScroll, VScrollMode::FullScroll);
        vdp.set_h_scroll(0, &[0, 0]);
        vdp.set_v_scroll(0, &[0, 0]);

        // Before anything is loaded: a reset here costs nothing, one
        // after the world is built would throw it all away.
        attest_clean_boot(&mut portal);

        wait_for_server_init(&mut vdp, &mut portal);

        let mut res_state = crate::resource_state::init(&mut vdp);

        // Load sprites that must not be evicted first.
        UI::preload_persistent_sprites(&mut res_state, &mut vdp);

        let mut player = Player::new(PlayerType::Shooter, &mut res_state, &mut vdp);

        Self::load_persistent_state(&portal);

        let captured_flags = flags_from_records(&portal);
        let defeated_minibosses = 0;

        // Build the map straight into its slot in `*this`: it is the largest
        // field, and routing through `Map::new` would stage a full Map temporary
        // on the stack. Done before `UI::new` to preserve resource load order.
        // SAFETY: `this` is valid for writes; `map` has not been initialised yet.
        unsafe {
            Map::emplace(
                core::ptr::addr_of_mut!((*this).map),
                MapType::Volcano,
                &mut res_state,
                &mut vdp,
                defeated_minibosses,
                &mut player,
            );
        }

        let ui = UI::new(&mut res_state, &mut vdp);

        emplace!(this, Self {
            vdp: vdp,
            res_state: res_state,
            portal: portal,
            renderer: renderer,
            controller: controller,
            ui: ui,
            defeated_minibosses: defeated_minibosses,
            captured_flags: captured_flags,
            score_frame: 0,
            player: player,
            state: GameState::StageSelect,
            dialogue: None,
            stage_select_scene: Some(StageSelect::with_boss_unlock_status(
                captured_flags >= FLAGS_FOR_BOSS,
            )),
            game_over_scene: None,
            win_scene: None,
            inventory_scene: InventoryScene::new(),
        } init_elsewhere: [map]);
    }

    /// Runs a game tick.
    ///
    /// # Panics
    /// When don't have a map set, or other weird things happen.
    pub fn update(&mut self) {
        self.next_cycle();

        let ctx = self;

        match ctx.state {
            GameState::Paused => {
                InventoryScene::update(ctx);
                if ctx
                    .controller
                    .controller_state(0)
                    .map(|i| i.just_pressed(Button::Start))
                    .unwrap_or(false)
                {
                    InventoryScene::on_exit(ctx);
                    ctx.state = GameState::Playing;
                    // Render sprites when fading in.
                    ctx.update_sprites();
                    fader::fade(ctx, fader::FadeMode::Out, fader::FadeColor::Black);
                    return;
                }
            }
            GameState::Playing => {
                if ctx
                    .controller
                    .controller_state(0)
                    .map(|i| i.just_pressed(Button::Start))
                    .unwrap_or(false)
                {
                    fader::fade(ctx, fader::FadeMode::In, fader::FadeColor::Black);
                    // Hide sprites in the pause menu
                    ctx.clear_sprites();
                    ctx.state = GameState::Paused;
                    InventoryScene::on_enter(ctx);
                    return;
                }

                Player::update(ctx);
                if matches!(ctx.player.status, player::Status::BeamingIn { .. }) {
                    // Game is frozen while the player enters the screen.
                    return;
                }

                Map::update(ctx);

                if ctx.player.is_dead() {
                    // Lose if the player is dead.
                    fader::fade(ctx, fader::FadeMode::In, fader::FadeColor::Black);
                    ctx.state = GameState::GameOver;
                    ctx.game_over_scene = Some(GameOver::new());
                    ctx.draw();
                    fader::fade(ctx, fader::FadeMode::Out, fader::FadeColor::Black);
                } else if Player::reset_pressed(ctx) {
                    ctx.switch_to_stage_select();
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
            GameState::StageSelect => {
                StageSelect::update(ctx);
            }
            GameState::GameOver => {
                GameOver::update(ctx);
            }
            GameState::Win => {
                YouWin::update(ctx);
            }
        }
    }

    /// Iterates to the next game frame and updates basic game elements
    /// that should happen on every tick.
    fn next_cycle(&mut self) {
        self.block_if_server_paused();
        self.controller.update();

        self.score_frame = self.score_frame.wrapping_add(1);
        self.portal.inform_game_tick();
        if self.score_frame % 500 == 0 {
            // Save state every 10s.
            self.save_persistent_state();
        }
    }

    pub fn draw(&mut self) {
        match self.state {
            GameState::StageSelect => {
                if let Some(scene) = self.stage_select_scene.as_mut() {
                    scene.render(&mut self.res_state, &mut self.vdp, &mut self.renderer);
                }
            }
            GameState::GameOver => {
                self.clear_sprites();
                if let Some(scene) = self.game_over_scene.as_mut() {
                    scene.render(&mut self.res_state, &mut self.vdp);
                }
            }
            GameState::Win => {
                self.clear_sprites();
                if let Some(scene) = self.win_scene.as_mut() {
                    scene.render(&self.ui, &mut self.res_state, &mut self.vdp);
                }
            }
            GameState::Paused => {
                self.clear_sprites();
                InventoryScene::render(self);
            }
            _ => {
                self.ui.render(
                    &self.player,
                    &self.map,
                    self.captured_flags,
                    self.score_frame,
                    &mut self.vdp,
                );
                if let Some(dialogue) = &mut self.dialogue {
                    dialogue.render(&self.ui, &mut self.vdp);
                }
                self.update_sprites();
            }
        }
        self.vdp.wait_for_vblank();
    }

    pub fn update_sprites(&mut self) {
        self.renderer.clear();

        if let Some(boss_state) = &mut self.map.boss_state {
            boss_state.render(&mut self.res_state, &mut self.vdp, &mut self.renderer);
        }

        for projectile in &mut self.map.projectiles {
            projectile.render(&mut self.res_state, &mut self.vdp, &mut self.renderer);
        }

        for item in &mut self.map.items {
            item.render(&mut self.res_state, &mut self.vdp, &mut self.renderer);
        }

        self.player
            .render(&mut self.res_state, &mut self.vdp, &mut self.renderer);

        for enemy in &mut self.map.enemies {
            enemy.render(&mut self.res_state, &mut self.vdp, &mut self.renderer);
        }

        for npc in &mut self.map.npcs {
            npc.render(&mut self.res_state, &mut self.vdp, &mut self.renderer);
        }

        for door in &mut self.map.doors {
            door.render(&mut self.res_state, &mut self.vdp, &mut self.renderer);
        }

        for switch in &mut self.map.switches {
            switch.render(&mut self.res_state, &mut self.vdp, &mut self.renderer);
        }

        self.renderer.render(&mut self.vdp)
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

    pub fn trigger_win(&mut self) {
        fader::fade(self, fader::FadeMode::Out, fader::FadeColor::White);
        self.state = GameState::Win;
        self.win_scene = Some(YouWin::new(self.score_frame));
        self.draw();
        fader::fade(self, fader::FadeMode::Out, fader::FadeColor::Black);
    }

    pub fn switch_to_stage_select(&mut self) {
        fader::fade(self, fader::FadeMode::In, fader::FadeColor::Black);
        self.game_over_scene = None;
        self.win_scene = None;
        self.state = GameState::StageSelect;
        self.stage_select_scene = Some(StageSelect::with_boss_unlock_status(self.boss_unlocked()));
        self.draw();
        fader::fade(self, fader::FadeMode::Out, fader::FadeColor::Black);
    }

    /// Load the map of the given [`MapType`] with the given [`PlayerType`]
    pub fn load_map(&mut self, new_map: MapType, player_type: PlayerType) {
        if matches!(new_map, MapType::BossStage) && self.captured_flags < FLAGS_FOR_BOSS {
            panic!("Insufficient flags to unlock boss");
        }

        self.portal.restrict_challenges(recordable_within(new_map));

        fader::fade(self, fader::FadeMode::In, fader::FadeColor::Black);

        self.stage_select_scene = None;

        // Unload prev map's tiles.
        self.res_state.reset();

        Inventory::clear(self);
        self.ui.clear();

        self.player = Player::new(player_type, &mut self.res_state, &mut self.vdp);

        // SAFETY: `map_ptr` is a valid, aligned pointer to the live `self.map`;
        // it is dropped and then fully re-initialised by `Map::emplace`.
        let defeated_minibosses = self.defeated_minibosses;
        unsafe {
            let map_ptr = core::ptr::addr_of_mut!(self.map);
            core::ptr::drop_in_place(map_ptr);
            Map::emplace(
                map_ptr,
                new_map,
                &mut self.res_state,
                &mut self.vdp,
                defeated_minibosses,
                &mut self.player,
            );
        }
        self.state = GameState::Playing;
        self.draw(); // Make sure sprites are updated.
        fader::fade(self, fader::FadeMode::Out, fader::FadeColor::Black);
    }

    /// The local palette of the current game context
    /// (e.g. the loaded map or scene).
    pub fn palette(&self, palette: Palette) -> [u16; 16] {
        let palette_type = if matches!(self.state, GameState::Paused) {
            palettes::PaletteContext::Inventory
        } else if self.stage_select_scene.is_some() {
            palettes::PaletteContext::StageSelect
        } else if self.game_over_scene.is_some() || self.win_scene.is_some() {
            palettes::PaletteContext::GameOver
        } else if matches!(palette, Palette::A) {
            return self.player.palette;
        } else {
            maps::palette_type(self.map.map_type)
        };
        palettes::get_palette(palette, palette_type)
    }

    pub fn boss_unlocked(&self) -> bool {
        self.captured_flags >= FLAGS_FOR_BOSS
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

    pub fn recompute_captured_flags(&mut self) {
        self.captured_flags = flags_from_records(&self.portal);
    }

    /// Check if the server is paused and block + display a loading text until it gets unpaused.
    fn block_if_server_paused(&mut self) {
        if matches!(self.portal.get_server_state(), ServerState::Running) {
            return;
        }

        let text = "Match paused, please stand by...";
        UI::draw_text(
            text,
            4,
            14,
            &self.ui.inventory_text_img,
            &mut self.vdp,
            Plane::B,
        );

        loop {
            self.vdp.wait_for_vblank();
            if matches!(self.portal.get_server_state(), ServerState::Running) {
                break;
            }
        }

        UI::clear_text(text, 4, 14, &mut self.vdp, Plane::B);
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

/// Makes sure a run is timed from a cleared game state.
fn attest_clean_boot(portal: &mut TargetPortal) {
    if portal.get_frame_count() != 0 {
        portal.request_console_reset();
    }
}

/// The KotH record slot a map's solve is recorded into.
///
/// Slots are keyed by map, which is what the `MAP_COUNT <=
/// KOTH_RECORD_SLOTS` assert below is protecting.
pub fn challenge_id(map: MapType) -> u8 {
    map as u8
}

/// The flag total earned so far, derived from the cartridge records.
fn flags_from_records(portal: &TargetPortal) -> u16 {
    let solved = |map| portal.get_challenge_record(challenge_id(map)) != KOTH_NO_RECORD;
    Map::get_flags_for_maps(
        solved(MapType::Forest),
        solved(MapType::Volcano),
        solved(MapType::Spaceship),
        solved(MapType::Arctic),
        solved(MapType::BossStage),
    )
}

/// Which challenges may still be recorded while playing `map`.
///
/// The boss is the one challenge that can hand the player code
/// execution, so entering it gives up the right to record a time for
/// anything else. The cartridge only ever ANDs this in, so a payload
/// cannot hand the permission back; only an attested reset restores it.
/// Adding another such area is one more arm here.
fn recordable_within(map: MapType) -> u16 {
    match map {
        MapType::BossStage => 1 << challenge_id(map),
        _ => u16::MAX,
    }
}

/// The game indexes record slots by MapType, so the cartridge must have
/// at least one slot per map. It currently has more; the spares are
/// headroom.
const _: () = assert!(MAP_COUNT <= KOTH_RECORD_SLOTS);

#[allow(dead_code)]
#[doc(hidden)]
const GAME_FITS_IN_RAM: () = {
    if core::mem::size_of::<Game<TargetControllers, TargetRenderer, TargetVdp, TargetPortal>>()
        > 32 * 1024 - 100
    {
        panic!("Game structure too large to fit in RAM (and remain copyable)");
    }
};

#[no_mangle]
pub extern "C" fn game_main() -> ! {
    static mut GAME: core::mem::MaybeUninit<
        Game<TargetControllers, TargetRenderer, TargetVdp, TargetPortal>,
    > = core::mem::MaybeUninit::uninit();

    // SAFETY: We are the only location that accesses GAME. It is initialised
    // exactly once, in place, before any reference to it is taken. Emplacing
    // directly into the static avoids building a full (~10KB) `Game` temporary
    // on game_main's stack first, which on the 68000's tiny RAM is the
    // difference between fitting and overflowing the stack into static data.
    let game = unsafe {
        let (vdp, renderer, controller, portal) = init_hardware();
        let p = core::ptr::addr_of_mut!(GAME)
            as *mut Game<TargetControllers, TargetRenderer, TargetVdp, TargetPortal>;
        Game::emplace(p, vdp, renderer, controller, portal);
        &mut *p
    };
    loop {
        game.update();
        game.draw();
    }
}
