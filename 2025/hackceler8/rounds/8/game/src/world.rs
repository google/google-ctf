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

use crate::enemy::boss::BossState;
use crate::entity::Entity;
use crate::game;
use crate::game::Ctx;
use crate::image;
use crate::map;
use crate::res::items::ItemType;
use crate::res::maps;
use crate::res::npcs::NpcType;
use crate::resource_state::State;
use crate::Direction;
use crate::Door;
use crate::Enemy;
use crate::Inventory;
use crate::Item;
use crate::Map;
use crate::Npc;
use crate::PlaneAddress;
use crate::PlaneWindow;
use crate::Player;
use crate::Projectile;
use crate::Switch;

const SCREEN_WIDTH: usize = 320;
const SCREEN_HEIGHT: usize = 224;
// Player sprite positions that should trigger screen scrolls.
const SCROLL_RIGHT_X: i16 = SCREEN_WIDTH as i16 + 128 - 7;
const SCROLL_DOWN_Y: i16 = SCREEN_HEIGHT as i16 + 128 - 14;
const SCROLL_LEFT_X: i16 = 128 - 7;
const SCROLL_UP_Y: i16 = 128 - 14;

#[macro_export]
macro_rules! assert_debug {
    ($check:expr, $msg:expr) => {
        if !$check {
            #[cfg(debug_assertions)]
            panic!($msg);
        }
    };
}

/// Describes the current state of a map transition
struct MapTransition {
    /// Total time of the transition in frames
    total_frame_count: u16,
    /// # of frames we are in the transition.
    frame_counter: u16,
    // Direction in which to transition
    direction: Direction,
    /// Next map to load
    next_map: Map,
}

/// A bitmask struct for tracking world object states such as collected
/// items and opened doors.
pub struct Bitmask(u16);

impl Bitmask {
    pub fn new() -> Self {
        Self(0)
    }

    pub fn all_set() -> Self {
        Self(0xFFFF)
    }

    pub fn is_set(&self, id: u16) -> bool {
        self.0 & (1 << id) != 0
    }

    pub fn set(&mut self, id: u16) {
        self.0 |= 1 << id;
    }

    pub fn clear(&mut self, id: u16) {
        self.0 &= !(1 << id);
    }
}

// A World comprises of several maps (rooms).
pub struct World {
    pub world_type: maps::WorldType,
    pub current_position: (i16, i16),

    // Describes the current scroll situation
    pub plane_window: PlaneWindow,

    pub map: Option<Map>,
    map_transition: Option<MapTransition>,
    pub enemies: heapless::Vec<Enemy, 8>,
    pub npcs: heapless::Vec<Npc, 16>,
    pub items: heapless::Vec<Item, 8>,
    items_collected: Bitmask,
    pub inventory: Inventory,
    pub doors: heapless::Vec<Door, 8>,
    pub doors_opened: Bitmask,
    pub switches: heapless::Vec<Switch, 8>,
    pub switches_completed: Bitmask,
    pub projectiles: heapless::Vec<Projectile, 8>,
    pub boss_state: Option<BossState>,
    /// Safe tiles to stand on in f22.tmx
    safe_tiles: Option<[(i16, i16); 6]>,
    pub rabbit_tile: Option<u16>,
}

impl World {
    /// Create a new [`World`].
    ///
    /// If world_position is set, it will overwrite the map
    /// that the player will spawn in.
    pub fn new(
        world_type: maps::WorldType,
        state: &mut State,
        vdp: &mut TargetVdp,
        defeated_minibosses: u16,
        captured_flags: u16,
        players: &mut [Player],
        world_position: Option<(i16, i16)>,
    ) -> Self {
        let initial_position = maps::start_coords(world_type);
        let mut world = World {
            world_type,
            current_position: initial_position,
            plane_window: PlaneWindow::new(),
            map: None,
            map_transition: None,
            enemies: heapless::Vec::new(),
            npcs: heapless::Vec::new(),
            items: heapless::Vec::new(),
            items_collected: Bitmask::new(),
            inventory: Inventory::new(),
            projectiles: heapless::Vec::new(),
            doors: heapless::Vec::new(),
            doors_opened: Bitmask::new(),
            switches: heapless::Vec::new(),
            switches_completed: Bitmask::new(),
            boss_state: None,
            safe_tiles: None,
            rabbit_tile: None,
        };

        match world_type {
            maps::WorldType::Overworld => {
                // Clear the path to the boss gate if enough flags have been captured.
                if captured_flags >= game::FLAGS_FOR_BOSS_TEMPLE {
                    world.doors_opened = Bitmask::all_set();
                }
            }
            maps::WorldType::BossTemple => {
                world.boss_state = Some(BossState::new(state, vdp));
            }
            _ => {}
        }

        let (x, y) = world_position.unwrap_or(initial_position);
        let map = maps::map(world_type, x, y).unwrap()();
        world.load_map(state, vdp, map, defeated_minibosses, players, x, y);
        world
    }

    fn load_map(
        &mut self,
        res_state: &mut State,
        vdp: &mut TargetVdp,
        mut map: Map,
        defeated_minibosses: u16,
        players: &mut [Player],
        x: i16,
        y: i16,
    ) {
        if self.map.is_none() {
            // First map - load map entities and player.
            // if the spawn position is not in the current map dont try to move the player
            // the game.rs will take care of that.
            if map.player_spawn_position.is_some() {
                let x = map.player_spawn_position.unwrap().0 + 128;
                let y = map.player_spawn_position.unwrap().1 + 128;
                for player in &mut *players {
                    let center: (i16, i16) = player.hitbox().center();
                    player.move_relative(x - center.0, y - center.1);
                }
            }
            if matches!(self.world_type, maps::WorldType::Overworld) {
                // Reset players when returning to the overworld.
                for player in &mut *players {
                    player.reset();
                }
            }
            self.load_enemies(res_state, vdp, defeated_minibosses, &map, 0, 0);
            self.load_npcs(res_state, vdp, &map, 0, 0);
            self.load_items(res_state, vdp, &map, 0, 0);
            self.load_doors(res_state, vdp, &map, 0, 0);
            self.load_switches(res_state, vdp, &map, 0, 0);

            self.plane_window = PlaneWindow::new();
            map.load_to_vram(self.plane_window.vram_address(), vdp, res_state);
        } else {
            // Remove objects of previous map.
            self.enemies.retain(|e| !map::off_screen(e.x, e.y));
            self.npcs.retain(|n| !map::off_screen(n.x, n.y));
            self.items.retain(|i| !map::off_screen(i.x, i.y));
            self.doors.retain(|d| !map::off_screen(d.x, d.y));
            self.switches.retain(|d| !map::off_screen(d.x, d.y));
            self.projectiles.retain(|p| !map::off_screen(p.x, p.y));
        }

        info!("load_map - updating current position to {} {}", x, y);
        self.current_position = (x, y);
        self.map = Some(map);
    }

    fn load_enemies(
        &mut self,
        res_state: &mut State,
        vdp: &mut TargetVdp,
        defeated_minibosses: u16,
        next_map: &Map,
        dx: i16,
        dy: i16,
    ) {
        for &(enemy_type, id, x, y, properties) in next_map.enemies {
            if properties.flags.is_some() && defeated_minibosses & enemy_type as u16 != 0 {
                // Miniboss already defeated
                continue;
            }
            let enemy = Enemy::new(enemy_type, x + dx, y + dy, id, properties, res_state, vdp);
            assert_debug!(self.enemies.push(enemy).is_ok(), "too many enemies");
        }
    }

    fn load_npcs(
        &mut self,
        res_state: &mut State,
        vdp: &mut TargetVdp,
        next_map: &Map,
        dx: i16,
        dy: i16,
    ) {
        for &(npc_type, x, y, properties) in next_map.npcs {
            let npc = Npc::new(npc_type, x + dx, y + dy, properties, res_state, vdp);
            assert_debug!(self.npcs.push(npc).is_ok(), "too many npcs");
        }
    }

    fn load_items(
        &mut self,
        res_state: &mut State,
        vdp: &mut TargetVdp,
        next_map: &Map,
        dx: i16,
        dy: i16,
    ) {
        for &(item_type, x, y, properties) in next_map.items {
            if self.items_collected.is_set(properties.id) {
                continue;
            }
            let item = Item::new(item_type, x + dx, y + dy, properties, res_state, vdp);
            assert_debug!(self.items.push(item).is_ok(), "too many items");
        }
    }

    fn load_doors(
        &mut self,
        res_state: &mut State,
        vdp: &mut TargetVdp,
        next_map: &Map,
        dx: i16,
        dy: i16,
    ) {
        for &(x, y, properties) in next_map.doors {
            let open = self.doors_opened.is_set(properties.id);
            let door = Door::new(
                self.world_type,
                x + dx,
                y + dy,
                properties,
                open,
                res_state,
                vdp,
            );
            assert_debug!(self.doors.push(door).is_ok(), "too many doors");
        }
    }

    fn load_switches(
        &mut self,
        res_state: &mut State,
        vdp: &mut TargetVdp,
        next_map: &Map,
        dx: i16,
        dy: i16,
    ) {
        for &(x, y, properties) in next_map.switches {
            let completed = self.switches_completed.is_set(properties.id);
            let switch = Switch::new(x + dx, y + dy, properties, completed, res_state, vdp);
            assert_debug!(self.switches.push(switch).is_ok(), "too many switches");
        }
    }

    pub fn shuffle_chests(&mut self, portal: &mut TargetPortal) {
        let mut filled_position = [false; 10];
        let mut found_chest = false;
        for npc in &mut self.npcs {
            if npc.npc_type != NpcType::ChestNpc && npc.npc_type != NpcType::MimicNpc {
                continue;
            }
            found_chest = true;

            let mut pos = (portal.get_random_int() % 10) as usize;
            if filled_position.iter().all(|x| *x) {
                panic!("All chest slots filled");
            }
            while filled_position[pos] {
                pos = (pos + 1) % 10;
            }
            filled_position[pos] = true;

            npc.set_position(128 + 52 + pos as i16 * 24, npc.y);
        }

        if found_chest {
            for _ in 0..5 {
                self.inventory.remove(ItemType::Key);
            }
        }
    }

    // Returns true if the player starts scrolling into a new map.
    pub fn update(ctx: &mut Ctx) -> bool {
        for enemy_id in 0..ctx.world.enemies.len() {
            Enemy::update(ctx, enemy_id);
        }
        ctx.world.enemies.retain(|e| !e.should_unload());

        BossState::update(ctx);

        for npc_id in 0..ctx.world.npcs.len() {
            Npc::update(ctx, npc_id);
        }

        Switch::update(ctx);

        for projectile_id in 0..ctx.world.projectiles.len() {
            Projectile::update(ctx, projectile_id);
        }
        ctx.world.projectiles.retain(|e| !e.should_unload());

        for item_id in 0..ctx.world.items.len() {
            let (id, item_type) = Item::update(ctx, item_id);
            if let Some(id) = id {
                ctx.world.items_collected.set(id);
            }
            if let Some(item_type) = item_type {
                ctx.world.inventory.add(item_type);
            }
        }
        ctx.world.items.retain(|i| !i.should_unload());

        if let Some(safe_tiles) = ctx.world.safe_tiles {
            for player in &mut ctx.players {
                if !player.is_active() {
                    continue;
                }
                if player.x >= 194 && player.x <= 360 {
                    let mut safe = false;
                    for i in 0..safe_tiles.len() - 1 {
                        let (x1, y1) = safe_tiles[i];
                        let (x2, y2) = safe_tiles[i + 1];
                        if player.x >= x1.min(x2) - 8
                            && player.x <= x2.max(x1) + 8
                            && player.y >= y1.min(y2) - 8
                            && player.y <= y2.max(y1) + 8
                        {
                            safe = true;
                            break;
                        }
                    }
                    if !safe {
                        player.kill(/*falling=*/ true);
                    }
                }
            }
        }

        World::maybe_scroll_maps(ctx)
    }

    // Scroll between two maps. Returns true if the transition has been completed.
    pub fn update_map_transition(ctx: &mut Ctx) -> bool {
        let world = &mut ctx.world;
        let vdp = &mut ctx.vdp;
        let res_state = &mut ctx.res_state;
        let mut mt = world.map_transition.take().unwrap();

        if mt.frame_counter == 0 {
            info!(
                "First transition call, scroll offset: {} {}",
                world.plane_window.current_scroll().0,
                world.plane_window.current_scroll().1,
            );
        }
        mt.frame_counter += 1;

        let mut per_frame_offset = mt.direction.to_offset();
        per_frame_offset.0 *= (SCREEN_WIDTH as u16 / mt.total_frame_count) as i16;
        per_frame_offset.1 *= (SCREEN_HEIGHT as u16 / mt.total_frame_count) as i16;

        // Move all objects.
        for player in &mut ctx.players {
            player.set_position(player.x - per_frame_offset.0, player.y - per_frame_offset.1);
        }
        for enemy in &mut world.enemies {
            enemy.set_position(enemy.x - per_frame_offset.0, enemy.y - per_frame_offset.1);
        }
        for npc in &mut world.npcs {
            npc.set_position(npc.x - per_frame_offset.0, npc.y - per_frame_offset.1);
        }
        for projectile in &mut world.projectiles {
            projectile.set_position(
                projectile.x - per_frame_offset.0,
                projectile.y - per_frame_offset.1,
            );
            projectile.reset_trajectory();
        }
        for item in &mut world.items {
            item.set_position(item.x - per_frame_offset.0, item.y - per_frame_offset.1);
        }
        for door in &mut world.doors {
            door.set_position(door.x - per_frame_offset.0, door.y - per_frame_offset.1);
        }
        for switch in &mut world.switches {
            switch.set_position(switch.x - per_frame_offset.0, switch.y - per_frame_offset.1);
        }

        let accumulated_offset = (
            per_frame_offset.0 * mt.frame_counter as i16,
            per_frame_offset.1 * mt.frame_counter as i16,
        );

        let cur = world.plane_window.offset(accumulated_offset);
        let addr = PlaneAddress::new(cur.0 / 8, cur.1 / 8);

        // Move the background.
        if per_frame_offset.0 != 0 {
            let total_scrolled_px = accumulated_offset.0.unsigned_abs() as usize;
            let (map_column_offset, vram_addr_offset) = match mt.direction {
                // If we are sliding to the left, insert new tiles at the left and load tiles from the
                // right side of the new map
                Direction::Left => (40 - total_scrolled_px.div_ceil(8), 0),
                // If we are sliding to the right, do the opposite.
                Direction::Right => (total_scrolled_px / 8, 40),
                _ => unreachable!(),
            };

            if total_scrolled_px < SCREEN_WIDTH {
                mt.next_map.load_tile_column(
                    map_column_offset as u16,
                    addr + (vram_addr_offset as i16, 0i16),
                    vdp,
                    res_state,
                );
            }
            vdp.set_h_scroll(0, &[-(cur.0 as i16), 0]);
        } else if per_frame_offset.1 != 0 {
            let total_scrolled_px = accumulated_offset.1.unsigned_abs() as usize;
            let (map_row_offset, vram_addr_offset) = match mt.direction {
                // If we are sliding to the left, insert new tiles at the left and load tiles from the
                // right side of the new map
                Direction::Up => (28 - total_scrolled_px.div_ceil(8), 0),
                // If we are sliding to the right, do the opposite.
                Direction::Down => (total_scrolled_px / 8, 28),
                _ => unreachable!(),
            };

            if total_scrolled_px < SCREEN_HEIGHT {
                mt.next_map.load_tile_row(
                    map_row_offset as u16,
                    addr + (0i16, vram_addr_offset as i16),
                    vdp,
                    res_state,
                );
            }
            vdp.set_v_scroll(0, &[cur.1 as i16, image::SCREEN_V_SCROLL]);
        }

        if mt.frame_counter == mt.total_frame_count {
            let dir = mt.direction.to_offset();
            world.load_map(
                &mut ctx.res_state,
                &mut ctx.vdp,
                mt.next_map,
                ctx.defeated_minibosses,
                &mut ctx.players,
                world.current_position.0 + dir.0,
                world.current_position.1 + dir.1,
            );

            world.plane_window = PlaneWindow::new();
            world.plane_window.scroll(cur.0 as i16, cur.1 as i16);
            info!(
                "Transition done, final scroll offset: ({} {}) -> {} {}",
                cur.0,
                cur.1,
                world.plane_window.current_scroll().0,
                world.plane_window.current_scroll().1,
            );

            // Move all players to the position of the player that triggered the transition.
            let mut new_pos = None;
            for player in &ctx.players {
                if player.is_alive()
                    && player.x <= SCROLL_RIGHT_X
                    && player.y <= SCROLL_DOWN_Y
                    && player.x >= SCROLL_LEFT_X
                    && player.y >= SCROLL_UP_Y
                {
                    new_pos = Some((player.x, player.y));
                }
            }
            if let Some((x, y)) = new_pos {
                for player in &mut ctx.players {
                    if player.is_alive() {
                        player.set_position(x, y);
                        player.set_idle();
                    }
                }
            }

            return true;
        }

        world.map_transition = Some(mt);
        false
    }

    // Returns true if map scrolling has been started.
    pub fn maybe_scroll_maps(ctx: &mut Ctx) -> bool {
        for player in &ctx.players {
            if !player.is_active() || !player.is_alive() {
                continue;
            }
            if player.x > SCROLL_RIGHT_X {
                World::scroll_maps(ctx, Direction::Right);
                return true;
            }
            if player.y > SCROLL_DOWN_Y {
                World::scroll_maps(ctx, Direction::Down);
                return true;
            }
            if player.x < SCROLL_LEFT_X {
                World::scroll_maps(ctx, Direction::Left);
                return true;
            }
            if player.y < SCROLL_UP_Y {
                World::scroll_maps(ctx, Direction::Up);
                return true;
            }
        }
        false
    }

    fn scroll_maps(ctx: &mut Ctx, direction: Direction) {
        let (x, y) = ctx.world.current_position;
        info!(
            "scroll_maps({:?}) | current_position: {} {}",
            direction, x, y
        );
        let world = &mut ctx.world;

        let (dx, dy) = direction.to_offset();
        let new_x = x.wrapping_add(dx);
        let new_y = y.wrapping_add(dy);

        let (w, h) = maps::dimensions(world.world_type);
        // If we go out of bounds -> Exit world
        if new_x as usize >= w || new_y as usize >= h {
            ctx.exiting_world = true;
            // Exit the world into the overworld.
            ctx.new_world = Some(maps::WorldType::Overworld);
            return;
        }

        let Some(initer) = maps::map(world.world_type, new_x, new_y) else {
            ctx.exiting_world = true;
            // Exit the world into the overworld.
            ctx.new_world = Some(maps::WorldType::Overworld);
            return;
        };
        let next_map = initer();

        // Add entities of the new map.
        world.load_enemies(
            &mut ctx.res_state,
            &mut ctx.vdp,
            ctx.defeated_minibosses,
            &next_map,
            320 * dx,
            224 * dy,
        );
        world.load_npcs(
            &mut ctx.res_state,
            &mut ctx.vdp,
            &next_map,
            320 * dx,
            224 * dy,
        );
        world.load_items(
            &mut ctx.res_state,
            &mut ctx.vdp,
            &next_map,
            320 * dx,
            224 * dy,
        );
        world.load_doors(
            &mut ctx.res_state,
            &mut ctx.vdp,
            &next_map,
            320 * dx,
            224 * dy,
        );
        world.load_switches(
            &mut ctx.res_state,
            &mut ctx.vdp,
            &next_map,
            320 * dx,
            224 * dy,
        );

        info!("Loaded next map, setting transition state.");

        // Load the BG of the new map to scroll in.
        let step_x = 5;
        let step_y = 4;
        let timer = if dy == 0 {
            SCREEN_WIDTH as u16 / step_x
        } else {
            SCREEN_HEIGHT as u16 / step_y
        };
        world.map_transition = Some(MapTransition {
            total_frame_count: timer,
            frame_counter: 0,
            direction,
            next_map,
        });
    }

    // Get the world that should load upon entering the current map's entrance.
    pub fn get_entered_world(ctx: &Ctx) -> maps::WorldType {
        match ctx.world.current_position {
            (0, 0) => maps::WorldType::FireTemple,
            (2, 0) => maps::WorldType::WaterTemple,
            (0, 2) => maps::WorldType::ForestTemple,
            (2, 2) => maps::WorldType::SkyTemple,
            (1, 1) => maps::WorldType::BossTemple,
            _ => panic!(
                "No temple data for overworld coordinate {:?}",
                ctx.world.current_position
            ),
        }
    }

    // Clears entities such as enemies, items, doors from the world.
    pub fn clear(&mut self) {
        self.enemies.clear();
        self.npcs.clear();
        self.items.clear();
        self.doors.clear();
        self.switches.clear();
        self.projectiles.clear();
    }

    /// Computes the number of flags received from defeating the given minibosses,
    /// specified in a bitmap.
    pub fn get_flags_for_minibosses(defeated_minibosses: u16) -> u16 {
        let mut captured_flags = 0;
        for map in maps::forest_temple::MAPS
            .iter()
            .chain(maps::fire_temple::MAPS.iter())
            .chain(maps::sky_temple::MAPS.iter())
            .chain(maps::water_temple::MAPS.iter())
        {
            if let Some(map) = map {
                for enemy in map().enemies {
                    if defeated_minibosses & enemy.0 as u16 > 0 {
                        if let Some(flags) = enemy.4.flags {
                            captured_flags += flags;
                        }
                    }
                }
            }
        }
        captured_flags
    }

    /// Load the death tiles (i.e. the safe tile positions) for f22.tmx.
    pub fn maybe_load_death_tiles(ctx: &mut Ctx) {
        if !matches!(ctx.world.world_type, maps::WorldType::FireTemple) {
            ctx.world.safe_tiles = None;
            return;
        }
        // Hack: Check for the presence of boots to ascertain we're in f22.tmx
        // (the item is only present there in that map in the water temple).
        if !ctx
            .world
            .items
            .iter()
            .any(|i| i.item_type == ItemType::Boots)
        {
            ctx.world.safe_tiles = None;
            return;
        }

        let x1 = ctx.portal.get_random_range(210, 280);
        let y1 = ctx.portal.get_random_range(160, 230);
        let x2 = ctx.portal.get_random_range(280, 340);
        ctx.world.safe_tiles = Some([
            (190, 252),
            (x1, 252),
            (x1, y1),
            (x2, y1),
            (x2, 252),
            (360, 252),
        ]);
    }
}
