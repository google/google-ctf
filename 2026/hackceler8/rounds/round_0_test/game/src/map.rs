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

use crate::enemy::boss::BossState;
use crate::entity::Entity;
use crate::game::Ctx;
use crate::map_data;
use crate::placement::emplace;
use crate::res::enemies::EnemyType;
use crate::res::maps;
use crate::resource_state::State;
use crate::Door;
use crate::Enemy;
use crate::Inventory;
use crate::Item;
use crate::MapData;
use crate::Npc;
use crate::PlaneWindow;
use crate::Player;
use crate::Projectile;
use crate::Switch;

pub const SCREEN_WIDTH: usize = 320;
pub const SCREEN_HEIGHT: usize = 224;
// Player sprite positions that should trigger screen scrolls.
const SCROLL_RIGHT_X: i16 = SCREEN_WIDTH as i16 + 128 - 140;
const SCROLL_DOWN_Y: i16 = SCREEN_HEIGHT as i16 + 128 - 100;
const SCROLL_LEFT_X: i16 = 128 + 140;
const SCROLL_UP_Y: i16 = 128 + 100;

/// A bitmask struct for tracking map object states such as collected
/// items and opened doors.
#[derive(PartialEq)]
pub struct Bitmask(u32);

impl Bitmask {
    pub fn new() -> Self {
        Self(0)
    }

    pub fn all_set() -> Self {
        Self(0xFFFFFFF)
    }

    pub fn is_set(&self, id: u16) -> bool {
        self.0 & (1 << (id as u32)) != 0
    }

    pub fn set(&mut self, id: u16) {
        self.0 |= 1 << (id as u32);
    }

    pub fn clear(&mut self, id: u16) {
        self.0 &= !(1 << (id as u32));
    }
}

// A Map describes the tiles and objects (enemies, NPCs, etc.) in a level.
pub struct Map {
    pub map_type: maps::MapType,

    /// Describes the current scroll situation
    /// In terms of the VDP address (mod 64)
    plane_window: PlaneWindow,
    /// In absolute xy pixel count
    pub scroll_offset: (i16, i16),

    /// Playthrough frames, incremented on every map tick.
    pub play_frame: u32,

    pub map_data: MapData,
    pub enemies: heapless::Vec<Enemy, 16>,
    pub enemies_loaded: Bitmask,
    pub enemies_defeated: Bitmask,
    pub npcs: heapless::Vec<Npc, 16>,
    pub npcs_loaded: Bitmask,
    pub items: heapless::Vec<Item, 16>,
    pub items_loaded: Bitmask,
    pub items_collected: Bitmask,
    pub item_start_tile: u16,
    pub inventory: Inventory,
    pub doors: heapless::Vec<Door, 16>,
    pub doors_loaded: Bitmask,
    pub doors_unlocked: Bitmask,
    pub doors_locked: Bitmask,
    pub switches: heapless::Vec<Switch, 16>,
    pub switches_loaded: Bitmask,
    pub switches_completed: Bitmask,
    pub projectiles: heapless::Vec<Projectile, 16>,
    pub boss_state: Option<BossState>,
}

impl Map {
    /// Create a new [`Map`].
    ///
    /// By-value convenience wrapper around [`Map::emplace`].
    pub fn new(
        map_type: maps::MapType,
        state: &mut State,
        vdp: &mut TargetVdp,
        defeated_minibosses: u32,
        player: &mut Player,
    ) -> Self {
        let mut map = core::mem::MaybeUninit::<Self>::uninit();
        // SAFETY: `emplace` fully initialises the `Map` behind the pointer.
        unsafe {
            Self::emplace(
                map.as_mut_ptr(),
                map_type,
                state,
                vdp,
                defeated_minibosses,
                player,
            );
            map.assume_init()
        }
    }

    /// Initialise a [`Map`] directly into `this` without building a by-value
    /// temporary (see [`crate::placement`]).
    ///
    /// # Safety
    /// `this` must point to writable, aligned, uninitialised memory for a `Map`.
    pub unsafe fn emplace(
        this: *mut Self,
        map_type: maps::MapType,
        state: &mut State,
        vdp: &mut TargetVdp,
        defeated_minibosses: u32,
        player: &mut Player,
    ) {
        emplace!(
            this,
            Self {
                map_type: map_type,
                plane_window: PlaneWindow::new(),
                scroll_offset: (0, 0),
                play_frame: 0,
                map_data: maps::map_data(map_type),
                enemies: heapless::Vec::new(),
                enemies_loaded: Bitmask::new(),
                enemies_defeated: Bitmask::new(),
                npcs: heapless::Vec::new(),
                npcs_loaded: Bitmask::new(),
                items: heapless::Vec::new(),
                items_loaded: Bitmask::new(),
                items_collected: Bitmask::new(),
                inventory: Inventory::new(player),
                item_start_tile: 0,
                projectiles: heapless::Vec::new(),
                doors: heapless::Vec::new(),
                doors_loaded: Bitmask::new(),
                doors_unlocked: Bitmask::new(),
                doors_locked: Bitmask::new(),
                switches: heapless::Vec::new(),
                switches_loaded: Bitmask::new(),
                switches_completed: Bitmask::new(),
                boss_state: None,
            }
        );

        // SAFETY: every field was just initialised above.
        let map = unsafe { &mut *this };
        if matches!(map_type, maps::MapType::BossStage)
            && defeated_minibosses & EnemyType::Boss as u32 == 0
        {
            map.boss_state = Some(BossState::new(state, vdp));
        }

        map.load_map(state, vdp, defeated_minibosses, player);
    }

    fn load_map(
        &mut self,
        res_state: &mut State,
        vdp: &mut TargetVdp,
        defeated_minibosses: u32,
        player: &mut Player,
    ) {
        // Load map entities and player.
        let px = self.map_data.player_spawn_position.0 + 128;
        let py = self.map_data.player_spawn_position.1 + 128;
        let center: (i16, i16) = player.hitbox().center();
        player.move_relative(px - center.0, py - center.1);

        let center = player.hitbox().center();

        // Position screen so the player is in the center.
        let mut scroll_x = 128 + 320 / 2 - center.0;
        let mut scroll_y = 128 + 224 / 2 - center.1;
        (scroll_x, scroll_y) = self.normalize((scroll_x, scroll_y));
        player.move_relative(scroll_x, scroll_y);
        player.reset();

        self.load_items(res_state, vdp, scroll_x, scroll_y);
        self.load_enemies(res_state, vdp, defeated_minibosses, scroll_x, scroll_y);
        self.load_npcs(res_state, vdp, scroll_x, scroll_y);
        self.load_doors(res_state, vdp, scroll_x, scroll_y);
        self.load_switches(res_state, vdp, scroll_x, scroll_y);

        self.scroll_offset = (-scroll_x, -scroll_y);
        self.plane_window = PlaneWindow::new();
        self.plane_window.scroll(-scroll_x % 8, -scroll_y % 8);
        self.reload_map_tiles(vdp, res_state);
    }

    /// Fully redraws the map plane after its tiles have been clobbered
    /// (e.g. by the full-screen pause menu).
    pub fn redraw(&mut self, vdp: &mut TargetVdp, res_state: &mut State) {
        self.plane_window = PlaneWindow::new();
        // reload_map_tiles / load_to_vram always anchor the map at VRAM
        // tile (0, 0), whereas during gameplay the content lives at a wrapped
        // offset tracked by `plane_window`. Re-anchoring at (0, 0) without
        // realigning the window would leave the tiles shifted relative to the
        // scroll registers. Rebuild the window from `scroll_offset` keeping only
        // the sub-tile component, exactly like `load_map` does on initial load.
        self.plane_window
            .scroll(self.scroll_offset.0 % 8, self.scroll_offset.1 % 8);
        self.reload_map_tiles(vdp, res_state);
    }

    pub fn reload_map_tiles(&mut self, vdp: &mut TargetVdp, res_state: &mut State) {
        let offs = self.plane_window.current_scroll();
        vdp.set_plane_size(ScrollSize::Cell64, ScrollSize::Cell64);
        vdp.set_h_scroll(0, &[-(offs.0 as i16), 0]);
        vdp.set_v_scroll(0, &[offs.1 as i16, 0]);

        self.map_data.load_to_vram(
            self.scroll_offset.0 / 8,
            self.scroll_offset.1 / 8,
            vdp,
            res_state,
        );
    }

    fn load_enemies(
        &mut self,
        res_state: &mut State,
        vdp: &mut TargetVdp,
        defeated_minibosses: u32,
        dx: i16,
        dy: i16,
    ) {
        for &(enemy_type, x, y, properties) in self.map_data.enemies {
            if properties.flags.is_some() && defeated_minibosses & enemy_type as u32 != 0 {
                // Miniboss already defeated
                continue;
            }
            if self.enemies_defeated.is_set(properties.id) {
                continue;
            }
            if is_off_screen(128 + x + dx, 128 + y + dy) {
                continue;
            }
            if self.enemies_loaded.is_set(properties.id) {
                continue;
            }
            self.enemies_loaded.set(properties.id);
            let enemy = Enemy::new(enemy_type, x + dx, y + dy, properties, res_state, vdp);
            self.enemies
                .push(enemy)
                .unwrap_or_else(|_| panic!("too many enemies"));
        }
    }

    fn load_npcs(&mut self, res_state: &mut State, vdp: &mut TargetVdp, dx: i16, dy: i16) {
        for &(npc_type, x, y, properties) in self.map_data.npcs {
            if is_off_screen(128 + x + dx, 128 + y + dy) {
                continue;
            }
            if self.npcs_loaded.is_set(properties.id) {
                continue;
            }
            self.npcs_loaded.set(properties.id);
            let npc = Npc::new(npc_type, x + dx, y + dy, properties, res_state, vdp);
            self.npcs
                .push(npc)
                .unwrap_or_else(|_| panic!("too many npcs"));
        }
    }

    fn load_items(&mut self, res_state: &mut State, vdp: &mut TargetVdp, dx: i16, dy: i16) {
        // Preload the sprites of all collectible items so their tiles is next to each other.
        for (i, item) in crate::res::items::ALL_ITEMS.iter().enumerate() {
            let sprite = crate::res::items::sprite_init_fn(*item)(
                res_state, vdp, /* singleton= */ false, /* keep_loaded= */ false,
            );
            if i == 0 {
                self.item_start_tile = sprite.vram_start_tile();
            }
        }

        for &(item_type, x, y, properties) in self.map_data.items {
            if self.items_collected.is_set(properties.id) {
                continue;
            }
            if is_off_screen(128 + x + dx, 128 + y + dy) {
                continue;
            }
            if self.items_loaded.is_set(properties.id) {
                continue;
            }
            self.items_loaded.set(properties.id);
            let item = Item::new(item_type, x + dx, y + dy, properties, res_state, vdp);
            self.items
                .push(item)
                .unwrap_or_else(|_| panic!("too many items"));
        }
    }

    fn load_doors(&mut self, res_state: &mut State, vdp: &mut TargetVdp, dx: i16, dy: i16) {
        for &(x, y, properties) in self.map_data.doors {
            if is_off_screen(128 + x + dx, 128 + y + dy) {
                continue;
            }
            if self.doors_loaded.is_set(properties.id) {
                continue;
            }
            self.doors_loaded.set(properties.id);
            let locked = (properties.locked || self.doors_locked.is_set(properties.id))
                && !self.doors_unlocked.is_set(properties.id);
            let is_open = properties.locked && self.doors_unlocked.is_set(properties.id);
            let door = Door::new(
                self.map_type,
                x + dx,
                y + dy,
                properties,
                is_open,
                locked,
                res_state,
                vdp,
            );
            self.doors
                .push(door)
                .unwrap_or_else(|_| panic!("too many doors"));
        }
    }

    fn load_switches(&mut self, res_state: &mut State, vdp: &mut TargetVdp, dx: i16, dy: i16) {
        for &(x, y, properties) in self.map_data.switches {
            if is_off_screen(128 + x + dx, 128 + y + dy) {
                continue;
            }
            if self.switches_loaded.is_set(properties.id) {
                continue;
            }
            self.switches_loaded.set(properties.id);
            let completed = self.switches_completed.is_set(properties.id);
            let switch = Switch::new(x + dx, y + dy, properties, completed, res_state, vdp);
            self.switches
                .push(switch)
                .unwrap_or_else(|_| panic!("too many switches"));
        }
    }

    pub fn update(ctx: &mut Ctx) {
        ctx.map.play_frame = ctx.map.play_frame.wrapping_add(1);

        for enemy_id in 0..ctx.map.enemies.len() {
            if Enemy::update(ctx, enemy_id) {
                ctx.map.enemies_defeated.set(ctx.map.enemies[enemy_id].id);
            }
            if ctx.map.enemies[enemy_id].should_unload() {
                ctx.map.enemies_loaded.clear(ctx.map.enemies[enemy_id].id);
            }
        }
        ctx.map.enemies.retain(|e| !e.should_unload());

        BossState::update(ctx);

        for npc_id in 0..ctx.map.npcs.len() {
            Npc::update(ctx, npc_id);
        }

        Switch::update(ctx);

        for door_id in 0..ctx.map.doors.len() {
            Door::update(ctx, door_id)
        }

        for projectile_id in 0..ctx.map.projectiles.len() {
            Projectile::update(ctx, projectile_id);
        }
        ctx.map.projectiles.retain(|e| !e.should_unload());

        for item_id in 0..ctx.map.items.len() {
            let (id, item_type) = Item::update(ctx, item_id);
            if let Some(item_type) = item_type {
                Inventory::add(ctx, item_type);
            }
            if let Some(id) = id {
                ctx.map.items_collected.set(id);
            }
            if ctx.map.items[item_id].should_unload() {
                ctx.map.items_loaded.clear(ctx.map.items[item_id].id);
            }
        }
        ctx.map.items.retain(|i| !i.should_unload());

        Map::maybe_scroll_map(ctx);
    }

    pub fn maybe_scroll_map(ctx: &mut Ctx) {
        let player = &mut ctx.player;
        let (dx, dy) = ctx.map.normalize(get_scroll(player));

        if dx == 0 && dy == 0 {
            return;
        }

        Map::scroll_tiles(ctx, dx, dy);
        Map::scroll_entities(ctx, dx, dy);
    }

    /// Scroll the map tiles by the specified amount and load any new tiles to VRAM.
    fn scroll_tiles(ctx: &mut Ctx, dx: i16, dy: i16) {
        let mut rem_x = dx;
        let mut rem_y = dy;
        while rem_x != 0 || rem_y != 0 {
            let step_x = rem_x.clamp(-8, 8);
            let step_y = rem_y.clamp(-8, 8);
            Map::scroll_tiles_step(ctx, step_x, step_y);
            rem_x -= step_x;
            rem_y -= step_y;
        }
    }

    /// Scroll the map tiles by at most one tile (8 px) in each axis, loading the
    /// single row/column of tiles that this exposes at the `plane_window` edge.
    fn scroll_tiles_step(ctx: &mut Ctx, dx: i16, dy: i16) {
        let map = &mut ctx.map;

        // Scroll background.
        map.scroll_offset.0 -= dx;
        map.scroll_offset.1 -= dy;
        map.plane_window.scroll(-dx, -dy);
        let offs = map.plane_window.current_scroll();
        ctx.vdp.set_h_scroll(0, &[-(offs.0 as i16), 0]);
        ctx.vdp.set_v_scroll(0, &[offs.1 as i16, 0]);

        // Load new map tiles.
        let mut start_x = map.scroll_offset.0 / 8;
        let mut end_x = (map.scroll_offset.0 + dx) / 8;
        let mut row_addr = map.plane_window.vram_address();
        if dx < 0 {
            (start_x, end_x) = (
                map_data::WIDTH as i16 + end_x + 1,
                map_data::WIDTH as i16 + start_x + 1,
            );
            row_addr.0 += map_data::WIDTH as u16
        }
        for x in start_x..end_x {
            map.map_data.load_tile_column(
                x,
                map.scroll_offset.1 / 8,
                row_addr,
                &mut ctx.vdp,
                &mut ctx.res_state,
            );
        }

        let mut start_y = map.scroll_offset.1 / 8;
        let mut end_y = (map.scroll_offset.1 + dy) / 8;
        let mut column_addr = map.plane_window.vram_address();
        if dy < 0 {
            (start_y, end_y) = (
                map_data::HEIGHT as i16 + end_y + 1,
                map_data::HEIGHT as i16 + start_y + 1,
            );
            column_addr.1 += map_data::HEIGHT as u16
        }
        for y in start_y..end_y {
            map.map_data.load_tile_row(
                map.scroll_offset.0 / 8,
                y,
                column_addr,
                &mut ctx.vdp,
                &mut ctx.res_state,
            );
        }
    }

    /// Moves entities as part of a map scroll by the specified amount.
    fn scroll_entities(ctx: &mut Ctx, dx: i16, dy: i16) {
        let map = &mut ctx.map;
        // Move all map entities.
        ctx.player.move_relative(dx, dy);
        for enemy in &mut map.enemies {
            enemy.move_relative(dx, dy);
        }
        for npc in &mut map.npcs {
            npc.move_relative(dx, dy);
        }
        for projectile in &mut map.projectiles {
            projectile.scroll(dx, dy);
        }
        for item in &mut map.items {
            item.move_relative(dx, dy);
        }
        for door in &mut map.doors {
            door.move_relative(dx, dy);
        }
        for switch in &mut map.switches {
            switch.move_relative(dx, dy);
        }

        // Remove out-of-screen entities.
        for e in &map.enemies {
            if is_off_screen(e.x, e.y) {
                map.enemies_loaded.clear(e.id);
            }
        }
        map.enemies.retain(|e| !is_off_screen(e.x, e.y));
        for n in &map.npcs {
            if is_off_screen(n.x, n.y) {
                map.npcs_loaded.clear(n.id);
            }
        }
        map.npcs.retain(|n| !is_off_screen(n.x, n.y));
        for i in &map.items {
            if is_off_screen(i.x, i.y) {
                map.items_loaded.clear(i.id);
            }
        }
        map.items.retain(|i| !is_off_screen(i.x, i.y));
        for d in &map.doors {
            if is_off_screen(d.x, d.y) {
                map.doors_loaded.clear(d.id);
            }
        }
        map.doors.retain(|d| !is_off_screen(d.x, d.y));
        for s in &map.switches {
            if is_off_screen(s.x, s.y) {
                map.switches_loaded.clear(s.id);
            }
        }
        map.switches.retain(|s| !is_off_screen(s.x, s.y));
        map.projectiles.retain(|p| !is_off_screen(p.x, p.y));


        // Add new on-screen entities.
        let scroll_x = -map.scroll_offset.0;
        let scroll_y = -map.scroll_offset.1;
        map.load_items(&mut ctx.res_state, &mut ctx.vdp, scroll_x, scroll_y);
        map.load_enemies(
            &mut ctx.res_state,
            &mut ctx.vdp,
            ctx.defeated_minibosses,
            scroll_x,
            scroll_y,
        );
        map.load_npcs(&mut ctx.res_state, &mut ctx.vdp, scroll_x, scroll_y);
        map.load_doors(&mut ctx.res_state, &mut ctx.vdp, scroll_x, scroll_y);
        map.load_switches(&mut ctx.res_state, &mut ctx.vdp, scroll_x, scroll_y);
    }

    /// Normalize a scroll offset such that scrolling the map by this much
    /// doesn't show anything past the map edges on the screen.
    fn normalize(&self, scroll: (i16, i16)) -> (i16, i16) {
        let mut dx = scroll.0.min(self.scroll_offset.0);
        dx = dx.max(self.scroll_offset.0 - (self.map_data.width * 8 - SCREEN_WIDTH) as i16);
        let mut dy = scroll.1.min(self.scroll_offset.1);
        dy = dy.max(self.scroll_offset.1 - (self.map_data.height * 8 - SCREEN_HEIGHT) as i16);
        (dx, dy)
    }

    /// Clears entities such as enemies, items, doors from the map.
    pub fn clear(&mut self) {
        self.enemies.clear();
        self.npcs.clear();
        self.items.clear();
        self.doors.clear();
        self.switches.clear();
        self.projectiles.clear();
    }

    /// Computes the number of flags earned for the maps that have been solved.
    pub fn get_flags_for_maps(
        forest_solved: bool,
        volcano_solved: bool,
        spaceship_solved: bool,
        arctic_solved: bool,
        boss_solved: bool,
    ) -> u16 {
        let mut captured_flags = 0;
        // Only ever one flag-carrying miniboss is live in a map at a time, so
        // the first one found is the map's payout.
        let flagcount = |enemies: &[(EnemyType, i16, i16, &crate::enemy::EnemyProperties)]| -> u16 {
            enemies
                .iter()
                .map(|x| x.3.flags)
                .find(|x| x.unwrap_or(0) > 0)
                .flatten()
                .unwrap_or(0)
        };

        if forest_solved {
            captured_flags += flagcount(maps::forest::ENEMIES);
        }
        if volcano_solved {
            captured_flags += flagcount(maps::volcano::ENEMIES);
        }
        if spaceship_solved {
            captured_flags += flagcount(maps::spaceship::ENEMIES);
        }
        if arctic_solved {
            captured_flags += flagcount(maps::arctic::ENEMIES);
        }
        if boss_solved {
            captured_flags += flagcount(maps::boss_stage::ENEMIES);
        }
        captured_flags
    }
}

pub fn is_off_screen(x: i16, y: i16) -> bool {
    let leeway = 50;
    x + leeway < 128 || x - leeway > 320 + 128 || y + leeway < 128 || y - leeway > 224 + 128
}

/// Returns the amount of horizontal and vertical scrolling
/// needed to get the given player on screen.
pub fn get_scroll(player: &Player) -> (i16, i16) {
    let center = player.hitbox().center();

    let (mut dx, mut dy) = (0, 0);
    if center.0 > SCROLL_RIGHT_X {
        dx = SCROLL_RIGHT_X - center.0;
    } else if center.0 < SCROLL_LEFT_X {
        dx = SCROLL_LEFT_X - center.0;
    }
    if center.1 > SCROLL_DOWN_Y {
        dy = SCROLL_DOWN_Y - center.1;
    } else if center.1 < SCROLL_UP_Y {
        dy = SCROLL_UP_Y - center.1;
    }

    (dx, dy)
}
