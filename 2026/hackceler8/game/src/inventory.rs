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
use heapless::Vec;
use megahx8::*;

use crate::fader;
use crate::game::Ctx;
use crate::image::Image;
use crate::res::images::item_box as ItemBoxImage;
use crate::res::items::ItemType;
use crate::res::maps::MapType;
use crate::weapon;
use crate::weapon::WeaponType;
use crate::Player;
use crate::PlayerType;

// The HUD lives on Plane B; while the inventory menu is open we scroll that plane up
// so it moves off the top of the screen (Map::redraw resets this to 0 on exit).
const HUD_HIDE_SCROLL: i16 = 96;
const HUD_HIDE_SCROLL_TILES: u16 = HUD_HIDE_SCROLL as u16 / 8;

// Allocate enough boxes to display all possible collectible items.
const ITEM_SLOT_LEN: usize = 8;
// Each slot box is 4x4 tiles. With this many items they sit edge-to-edge.
const SLOT_SIZE: u16 = 4;
// Each item is 2x2 tiles.
const ITEM_SIZE: u16 = 2;
// Stride(width + padding) for each slot
const SLOT_STRIDE: u16 = SLOT_SIZE;
// On-screen tile rows for the item grid.
const ITEMS_LABEL_Y: u16 = 16;
const ITEMS_MARKER_Y: u16 = 17; // selection marker, just above the boxes
const ITEMS_ROW_Y: u16 = 18;
const ITEMS_COUNT_Y: u16 = ITEMS_ROW_Y + SLOT_SIZE; // count, just below the boxes
                                                    // Width of the whole slot row and its centered start column.
const ITEMS_ROW_W: u16 = (ITEM_SLOT_LEN as u16 - 1) * SLOT_STRIDE + SLOT_SIZE;
const ITEMS_ROW_X: u16 = (40 - ITEMS_ROW_W) / 2;

// Weapon-selection list layout (one row per weapon the character can wield).
const WEAPON_LABEL_Y: u16 = 11;
const WEAPON_LIST_Y: u16 = 12;
const WEAPON_ARROW_X: u16 = 4;
const WEAPON_NAME_X: u16 = 6;
const WEAPON_BAR_X: u16 = 20;
// Number of cells in a bar.
const BAR_LEN: u16 = 8;

pub struct InventoryItem {
    pub item_type: ItemType,
    pub amount: u16,
}

pub struct InventoryWeapon {
    pub weapon_type: WeaponType,
    pub uses_left: Option<i16>,
}

pub struct Inventory {
    pub items: Vec<InventoryItem, ITEM_SLOT_LEN>,
    pub weapons: Vec<InventoryWeapon, 16>,
    pub scene: Option<InventoryScene>,
}

impl Inventory {
    pub fn new(player: &Player) -> Inventory {
        Inventory {
            items: Vec::new(),
            weapons: weapon::DEFAULT_WEAPONS
                .iter()
                .filter(|w| w.player_type() == player.player_type)
                .map(|w| InventoryWeapon {
                    weapon_type: *w,
                    uses_left: w.max_uses(),
                })
                .collect(),
            scene: None,
        }
    }

    // Adds an item to the inventory.
    pub fn add(ctx: &mut Ctx, item_type: ItemType) {
        // Group multiple instances of items together.
        for i in &mut ctx.map.inventory.items {
            if i.item_type == item_type {
                i.amount += 1;
                return;
            }
        }

        ctx.map
            .inventory
            .items
            .push(InventoryItem {
                item_type,
                amount: 1,
            })
            .unwrap_or_else(|_| panic!("too many items in inventory"));
    }

    // Removes all items.
    pub fn clear(ctx: &mut Ctx) {
        ctx.map.inventory.items = Vec::new();
    }

    // Checks if there's at least one of the specified item type in the inventory
    pub fn contains(&self, item_type: ItemType) -> bool {
        #[cfg(feature = "god_mode")]
        if matches!(
            item_type,
            ItemType::Doublejump | ItemType::Dash | ItemType::Walljump | ItemType::Airdash
        ) {
            return true;
        }

        self.items.iter().any(|i| i.item_type == item_type)
    }

    // Removes one instance of a specified item type from the inventory.
    pub fn remove(&mut self, item_type: ItemType) {
        self.items
            .iter_mut()
            .find(|i| i.item_type == item_type)
            .map(|i| i.amount -= 1);
        self.items.retain(|i| i.amount > 0);
    }

    /// Whether the given weapon has any available uses left.
    pub fn weapon_has_uses_left(&self, weapon_type: WeaponType) -> bool {
        for w in &self.weapons {
            if w.weapon_type == weapon_type {
                if w.uses_left.is_some() && w.uses_left.unwrap() == 0 {
                    return false;
                }
            }
        }
        true
    }

    /// Decrement the uses_left counter of the given weapon.
    pub fn get_weapon_uses_left(&self, weapon_type: WeaponType) -> Option<i16> {
        self.weapons
            .iter()
            .find(|w| w.weapon_type == weapon_type)
            .map(|w| w.uses_left)
            .unwrap_or(None)
    }

    /// Incremend or decrement the uses_left counter of the given weapon.
    pub fn decrease_weapon_uses(&mut self, weapon_type: WeaponType) {
        self.change_weapon_uses(weapon_type, -1);
    }

    pub fn increase_weapon_uses(&mut self, weapon_type: WeaponType) {
        self.change_weapon_uses(weapon_type, 1);
    }

    pub fn change_weapon_uses(&mut self, weapon_type: WeaponType, amount: i16) {
        self.weapons
            .iter_mut()
            .find(|w| w.weapon_type == weapon_type)
            .map(|w| {
                if w.uses_left.is_some() {
                    w.uses_left = Some(w.uses_left.unwrap() + amount)
                }
            });
    }
}

/// The inventory display that gets rendered in the inventory menu.
pub struct InventoryScene {
    /// The index of the item currently being selected.
    pub selection: Option<usize>,
    /// Whether the scene should be updated in the next render call.
    pub needs_refresh: bool,
}

impl InventoryScene {
    pub fn new() -> Self {
        Self {
            selection: None,
            needs_refresh: false,
        }
    }

    /// Redraw the parts of the inventory menu that can change while it's open: the
    /// weapon list (selection + uses bars) and the item grid (icons, counts,
    /// selection marker). Runs every frame the menu is visible.
    pub fn render(ctx: &mut Ctx) {
        if let Some(scene) = &mut ctx.map.inventory.scene {
            if !scene.needs_refresh {
                return;
            }
            scene.needs_refresh = false;
        }
        Self::draw_weapons(ctx);
        Self::draw_items_dynamic(ctx);
    }

    pub fn on_enter(ctx: &mut Ctx) {
        // Activate the inventory scene so update() processes menu input while
        // GameState::Paused is active.
        ctx.map.inventory.scene = Some(InventoryScene::new());

        // The HUD (health, flags, boss bar) lives on Plane B in the top few rows.
        // The menu's transparent interior would let it show through, and priority
        // bits can't hide a transparent pixel. Plane B holds nothing but the HUD,
        // so scroll it up and off the top of the screen instead; Map::redraw resets
        // this back to 0 on exit, bringing the HUD back without a redraw.
        for row in 0..32 {
            ctx.vdp.set_plane_tiles(
                Plane::A,
                64 * row,
                &[TileFlags::for_tile(0, Palette::A); 40],
            );
        }

        ctx.vdp.set_h_scroll(0, &[0, 0]);
        ctx.vdp.set_v_scroll(0, &[0, HUD_HIDE_SCROLL]);

        // Solid frame around the whole screen.
        let border_tile = *TileFlags::for_tile(1, Palette::C).set_priority(true);
        let row_of_border = [border_tile; 40];
        ctx.vdp.set_plane_tiles(Plane::A, 0, &row_of_border);
        for y in 1..27 {
            for x in [0, 39] {
                ctx.vdp
                    .set_plane_tiles(Plane::A, 64 * y + x, &[border_tile]);
            }
        }
        ctx.vdp.set_plane_tiles(Plane::A, 64 * 27, &row_of_border);

        Self::draw_text_centered("== GAME PAUSED ==", 2, ctx);

        // Snapshot the static stats. The game is frozen while paused, so these
        // are drawn once here; render() only refreshes the dynamic sections.
        let map_type = ctx.map.map_type;
        let player = &ctx.player;
        let health = player.health;
        let max_health = player.max_health;

        const LABEL_X: u16 = 5;
        const VALUE_X: u16 = 16;

        Self::draw_label("Stage:", LABEL_X, 4, ctx);
        Self::draw_label(Self::map_name(map_type), VALUE_X, 4, ctx);

        Self::draw_label("Health:", LABEL_X, 5, ctx);
        Self::draw_health(health, max_health, VALUE_X, 5, ctx);

        let mut x = 2;
        Self::draw_label("Flag score speed:", x, 7, ctx);

        for &map_type in crate::res::maps::ALL_MAP_TYPES {
            let name = Self::map_name(map_type);
            Self::draw_label(name, x, 8, ctx);
            // The cartridge records are the source of truth: they also hold the solves the server restored after a reset.
            let record = ctx.portal.get_challenge_record(crate::game::challenge_id(map_type));
            let mut frame_str: String<8> = String::new();
            if record == KOTH_NO_RECORD {
                let _ = write!(frame_str, "-");
            } else {
                let _ = write!(frame_str, "{}", record);
            }
            Self::draw_label(&frame_str, x, 9, ctx);
            // max(6) is because the frame count can use 6 chars (e.g. 108000 for 30 mins run)
            x += name.len().max(6) as u16 + 1;
        }

        Self::draw_label("Weapons:", LABEL_X, WEAPON_LABEL_Y, ctx);
        Self::draw_label("Items:", LABEL_X, ITEMS_LABEL_Y, ctx);

        // The item boxes (Plane B) never change, so draw them once. Icons,
        // counts, the selection marker and the weapon list are drawn now and
        // kept up to date every frame by render().
        Self::draw_item_boxes(ctx);
        Self::draw_weapons(ctx);
        Self::draw_items_dynamic(ctx);

        Self::draw_text_centered("L/R: item      U/D: weapon      B: use", 23, ctx);
        Self::draw_text_centered("Press START to resume", 25, ctx);

        fader::fade(ctx, fader::FadeMode::Out, fader::FadeColor::Black);
    }

    /// Draw the weapon list: one row per weapon the character can wield, with a
    /// `>` marker on the equipped one and a uses bar for weapons that deplete.
    fn draw_weapons(ctx: &mut Ctx) {
        let selected = ctx.player.weapon;
        // Snapshot (type, uses_left) so we don't borrow the inventory while
        // drawing (which borrows ctx.vdp / ctx.ui).
        let mut entries: Vec<(WeaponType, Option<i16>), 16> = Vec::new();
        for w in &ctx.map.inventory.weapons {
            let _ = entries.push((w.weapon_type, w.uses_left));
        }

        for (i, (weapon_type, uses_left)) in entries.iter().enumerate() {
            let y = WEAPON_LIST_Y + i as u16;
            // Equipped-weapon marker (a space clears it on the other rows).
            Self::draw_label(
                if *weapon_type == selected { ">" } else { " " },
                WEAPON_ARROW_X,
                y,
                ctx,
            );
            Self::draw_label(weapon_type.display_name(), WEAPON_NAME_X, y, ctx);

            // Only weapons with a finite number of uses show a charge bar.
            if let Some(max) = weapon_type.max_uses() {
                let uses = uses_left.unwrap_or(0).max(0) as u16;
                // Draw a bar showing how many uses a weapon has left.
                Self::draw_bar(uses, max as u16, WEAPON_BAR_X, y, ctx);
            }
        }
    }

    /// Draw a `[####----] n/m` bar to show how much of a certain value is left.
    fn draw_bar(amount: u16, max: u16, x: u16, y: u16, ctx: &mut Ctx) {
        let filled = if max == 0 {
            0
        } else {
            (amount * BAR_LEN / max).min(BAR_LEN)
        };
        let mut bar: String<20> = String::new();
        let _ = bar.push('[');
        for cell in 0..BAR_LEN {
            let _ = bar.push(if cell < filled { '#' } else { '-' });
        }
        let _ = bar.push(']');
        let _ = write!(bar, " {}/{}", amount, max);
        Self::draw_label(&bar, x, y, ctx);
    }

    /// Draw the (static) item slot boxes on Plane B.
    ///
    /// The boxes are drawn *without* the priority bit so the transparent pixels
    /// of the item sprites (drawn on Plane A) reveal the box behind them.
    fn draw_item_boxes(ctx: &mut Ctx) {
        let box_plane_y = ITEMS_ROW_Y + HUD_HIDE_SCROLL_TILES;
        let item_box = ItemBoxImage::new(
            &mut ctx.res_state,
            &mut ctx.vdp,
            /* keep_loaded= */ false,
        );
        for i in 0..ITEM_SLOT_LEN {
            let slot_x = ITEMS_ROW_X + i as u16 * SLOT_STRIDE;
            Image::draw_low_priority(&item_box, slot_x, box_plane_y, &mut ctx.vdp, Plane::B);
        }
    }

    /// Draw the dynamic per-slot item content on Plane A: the sprite of each
    /// collected item (empty box otherwise), a stacked-count readout, and a
    /// marker over the currently selected item.
    fn draw_items_dynamic(ctx: &mut Ctx) {
        // Resolve item types and held amounts before borrowing the vdp for drawing.
        let mut items = [(ItemType::Key, 0u16); ITEM_SLOT_LEN];
        for (i, item) in ctx.map.inventory.items.iter().enumerate() {
            items[i] = (item.item_type, item.amount);
        }

        // The selection is a grid-slot index into inventory.items.
        let selected_slot = ctx
            .map
            .inventory
            .scene
            .as_ref()
            .and_then(|scene| scene.selection);

        for i in 0..ITEM_SLOT_LEN {
            let slot_x = ITEMS_ROW_X + i as u16 * SLOT_STRIDE;
            let item_type = items[i].0;
            let amount = items[i].1;

            // Selection marker above the slot (space clears it elsewhere).
            Self::draw_label(
                if Some(i) == selected_slot { "v" } else { " " },
                slot_x + SLOT_SIZE / 2,
                ITEMS_MARKER_Y,
                ctx,
            );

            // Item sprite, or clear the icon area to show the empty box.
            if amount > 0 {
                Self::draw_item_icon(item_type, slot_x, ITEMS_ROW_Y, ctx);
            } else {
                Self::clear_icon_area(slot_x, ITEMS_ROW_Y, ctx);
            }

            // Fixed-width count field (padded so stale digits get overwritten).
            let mut count: String<4> = String::new();
            if amount > 1 {
                let _ = write!(count, "x{}", amount);
            }
            while count.len() < 3 {
                let _ = count.push(' ');
            }
            Self::draw_label(&count, slot_x + 1, ITEMS_COUNT_Y, ctx);
        }
    }

    /// Clear the Plane A icon area of a slot (revealing the empty box on Plane B).
    fn clear_icon_area(slot_x: u16, slot_y: u16, ctx: &mut Ctx) {
        for cy in 0..SLOT_SIZE {
            for cx in 0..SLOT_SIZE {
                Image::clear_tile(slot_x + cx, slot_y + cy, &mut ctx.vdp, Plane::A);
            }
        }
    }

    /// Clear the Plane B item slots drawn by [`Self::draw_item_boxes`] so they
    /// don't remain visible on the HUD plane once the inventory menu closes.
    fn clear_items(ctx: &mut Ctx) {
        let box_plane_y = ITEMS_ROW_Y + HUD_HIDE_SCROLL_TILES;
        for row in 0..SLOT_SIZE {
            for col in 0..ITEMS_ROW_W {
                Image::clear_tile(ITEMS_ROW_X + col, box_plane_y + row, &mut ctx.vdp, Plane::B);
            }
        }
    }

    /// Draw an item's sprite centered within a 4x4 slot at `(slot_x, slot_y)`.
    fn draw_item_icon(item_type: ItemType, slot_x: u16, slot_y: u16, ctx: &mut Ctx) {
        let start_tile = ctx.map.item_start_tile + (item_type as u16) * ITEM_SIZE * ITEM_SIZE;
        let off_x = slot_x + (SLOT_SIZE - ITEM_SIZE) / 2;
        let off_y = slot_y + (SLOT_SIZE - ITEM_SIZE) / 2;

        for tx in 0..ITEM_SIZE {
            for ty in 0..ITEM_SIZE {
                // Mega Drive sprite tiles are stored column-major in VRAM.
                let tile = start_tile + tx * ITEM_SIZE + ty;
                ctx.vdp.set_plane_tiles(
                    Plane::A,
                    (off_y + ty) * 64 + (off_x + tx),
                    &[*TileFlags::for_tile(tile, Palette::B).set_priority(true)],
                );
            }
        }
    }

    /// Draw left-aligned text on the inventory plane.
    fn draw_label(text: &str, x: u16, y: u16, ctx: &mut Ctx) {
        crate::UI::draw_text(
            text,
            x,
            y,
            &ctx.ui.inventory_text_img,
            &mut ctx.vdp,
            Plane::A,
        );
    }

    /// Draw text horizontally centered on the 40-tile-wide screen.
    fn draw_text_centered(text: &str, y: u16, ctx: &mut Ctx) {
        let x = (40u16.saturating_sub(text.len() as u16)) / 2;
        Self::draw_label(text, x, y, ctx);
    }

    /// Draw the player's health as a numeric readout.
    fn draw_health(health: u16, max_health: u16, x: u16, y: u16, ctx: &mut Ctx) {
        Self::draw_bar(health, max_health as u16, x, y, ctx)
    }

    fn map_name(map_type: MapType) -> &'static str {
        match map_type {
            MapType::BossStage => "Boss",
            MapType::Volcano => "Volcano",
            MapType::Forest => "Forest",
            MapType::Spaceship => "SpShip",
            MapType::Arctic => "Arctic",
        }
    }

    pub fn on_exit(ctx: &mut Ctx) {
        fader::fade(ctx, fader::FadeMode::In, fader::FadeColor::Black);
        // Deactivate the scene and wipe the Plane B item boxes (the HUD plane)
        // before the regular HUD comes back, or they'd linger over gameplay.
        ctx.map.inventory.scene = None;
        Self::clear_items(ctx);
        ctx.map.redraw(&mut ctx.vdp, &mut ctx.res_state);
    }

    pub fn update(ctx: &mut Ctx) {
        let inventory = &mut ctx.map.inventory;
        let mut refresh_ui = false;
        let player = &mut ctx.player;
        if !player.is_active() {
            return;
        }

        if let Some(input) = ctx.controller.controller_state(0) {
            // The scene is kept Some by on_enter while the menu is open.
            if let Some(scene) = &mut inventory.scene {
                // Move the item selection with Left/Right.
                if input.just_pressed(Button::Right) {
                    // Move item selection forward.
                    if let Some(selection) = scene.selection {
                        scene.selection = Some(if selection < ITEM_SLOT_LEN - 1 {
                            selection + 1
                        } else {
                            0
                        });
                    } else {
                        scene.selection = Some(0);
                    }
                    refresh_ui = true;
                } else if input.just_pressed(Button::Left) {
                    // Move item selection backward.
                    if let Some(selection) = scene.selection {
                        scene.selection = Some(if selection > 0 {
                            selection - 1
                        } else {
                            ITEM_SLOT_LEN - 1
                        });
                    } else {
                        scene.selection = Some(ITEM_SLOT_LEN - 1);
                    }
                    refresh_ui = true;
                } else if input.just_pressed(Button::Down) || input.just_pressed(Button::Up) {
                    // Cycle the equipped weapon with Up/Down.
                    let forward = input.just_pressed(Button::Down);
                    let count = inventory.weapons.len();
                    if count > 0 {
                        for (i, w) in inventory.weapons.iter().enumerate() {
                            if w.weapon_type == player.weapon {
                                let next = if forward {
                                    (i + 1) % count
                                } else {
                                    (i + count - 1) % count
                                };
                                let next_weapon = inventory.weapons[next].weapon_type;
                                player.set_weapon(next_weapon, &mut ctx.res_state, &mut ctx.vdp);
                                if matches!(player.player_type, PlayerType::Shooter) {
                                    // Remove old weapon's projectiles to prevent graphical glitches.
                                    ctx.map.projectiles.retain(|p| !p.is_player);
                                }
                                break;
                            }
                        }
                        refresh_ui = true;
                    }
                }

                // Use the selected item.
                if player.is_alive() && input.just_pressed(Button::B) {
                    // Map the selected grid slot to its item type.
                    let selected_item = scene
                        .selection
                        .and_then(|slot| inventory.items.get(slot))
                        .and_then(|item| Some(item.item_type));
                    if selected_item == Some(ItemType::Battery) {
                        // Recharge the selected weapon's uses from a battery.
                        let uses_left = inventory.get_weapon_uses_left(player.weapon);
                        if let Some(max_uses) = player.weapon.max_uses() {
                            if uses_left.unwrap_or(0) < max_uses {
                                inventory.remove(ItemType::Battery);
                                inventory.increase_weapon_uses(player.weapon);
                                refresh_ui = true;
                            }
                        }
                    }
                }
            }
        }
        if refresh_ui {
            if let Some(scene) = &mut inventory.scene {
                scene.needs_refresh = true;
            }
        }
    }
}
