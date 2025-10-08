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

use crate::game::Ctx;
use crate::res::items::ItemType;
use crate::Player;

pub const MAX_ITEMS: usize = 16;
// Items that can be equipped by a player.
const WEARABLE_ITEMS: &[ItemType] = &[ItemType::Boots, ItemType::Goggles, ItemType::Sword];

pub struct InventoryItem {
    pub item_type: ItemType,
    pub amount: u16,
    // The index of the player this item is worn by.
    pub worn_by: Option<usize>,
}

pub struct Inventory {
    pub items: Vec<InventoryItem, MAX_ITEMS>,
    pub scene: Option<InventoryScene>,
}

impl Default for Inventory {
    fn default() -> Self {
        Self::new()
    }
}

impl Inventory {
    pub fn new() -> Inventory {
        Inventory {
            items: Vec::new(),
            scene: None,
        }
    }

    // Adds an item to the inventory.
    pub fn add(&mut self, item_type: ItemType) {
        // Group multiple instances of a non-wearable items together.
        if !InventoryItem::is_wearable(item_type) {
            for i in &mut self.items {
                if i.item_type == item_type {
                    i.amount += 1;
                    return;
                }
            }
        }

        self.items
            .push(InventoryItem {
                item_type,
                amount: 1,
                worn_by: None,
            })
            .unwrap_or_else(|_| panic!("too many items in inventory"));
    }

    // Removes all items and unequips them from players.
    pub fn clear(ctx: &mut Ctx) {
        for i in &mut ctx.world.inventory.items {
            i.unequip(&mut ctx.players);
        }
        ctx.world.inventory.items = Vec::new();
    }

    // Checks if there's at least one of the specified item type in the inventory
    pub fn contains(&self, item_type: ItemType) -> bool {
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
}

impl InventoryItem {
    /// Equip the item to a specified player and remove it from the previous player.
    pub fn equip(&mut self, players: &mut [Player], player_id: usize) {
        if let Some(worn_by) = self.worn_by {
            self.remove_effect(&mut players[worn_by]);
        }
        self.worn_by = Some(player_id);
        self.apply_effect(&mut players[player_id]);
    }

    /// Unequip the item from its current player.
    pub fn unequip(&mut self, players: &mut [Player]) {
        if let Some(worn_by) = self.worn_by {
            self.remove_effect(&mut players[worn_by]);
        }
        self.worn_by = None;
    }

    /// Whether the item of the given type can be equipped by a player.
    pub fn is_wearable(item_type: ItemType) -> bool {
        WEARABLE_ITEMS.contains(&item_type)
    }

    /// The string that should be displayed for a given item in the inventory.
    pub fn display_name(&self) -> &str {
        match self.item_type {
            ItemType::HeartItem => "Heart",
            ItemType::Boots => "Boots",
            ItemType::Goggles => "Goggles",
            ItemType::Sword => "Sword",
            ItemType::Key => "Key",
            ItemType::InvisibleKey => "Key",
        }
    }

    /// Apply the item's effects on a player.
    pub fn apply_effect(&self, player: &mut Player) {
        match self.item_type {
            ItemType::Boots => {
                player.speed += crate::player::SPEED_SCALE_FACTOR;
            }
            ItemType::Goggles => {
                player.health += 3;
                player.max_health += 3;
            }
            ItemType::Sword => {
                player.strength += 1;
            }
            _ => {}
        };
    }

    /// Remove the item's effects from a player it was previously applied to.
    pub fn remove_effect(&self, player: &mut Player) {
        match self.item_type {
            ItemType::Boots => {
                if player.speed > crate::player::SPEED_SCALE_FACTOR {
                    player.speed -= crate::player::SPEED_SCALE_FACTOR;
                }
            }
            ItemType::Goggles => {
                player.max_health -= 3;
                if player.health <= 3 {
                    player.kill(false);
                } else {
                    player.health -= 3;
                }
            }
            ItemType::Sword => {
                player.strength -= 1;
            }
            _ => {}
        };
    }
}

/// The inventory display that gets rendered in the pause menu.
pub struct InventoryScene {
    /// The index of the item currently being selected.
    /// All players control the same selection.
    pub selection: Option<usize>,
}

impl InventoryScene {
    pub fn update(ctx: &mut Ctx) {
        let inventory = &mut ctx.world.inventory;
        let players = &mut ctx.players;
        let mut refresh_ui = || ctx.ui.mark_inventory_for_refresh();

        for player_id in 0..players.len() {
            if let Some(input) = ctx.controller.controller_state(player_id) {
                if !players[player_id].active {
                    continue;
                }

                if input.just_pressed(Button::Start) {
                    inventory.scene = if matches!(inventory.scene, None) {
                        Some(InventoryScene { selection: None })
                    } else {
                        None
                    };
                    refresh_ui();
                }

                if let Some(scene) = &mut inventory.scene {
                    // Move selection
                    let item_count = inventory.items.len();
                    if input.just_pressed(Button::Down) {
                        if let Some(selection) = scene.selection {
                            scene.selection = Some(if selection < item_count - 1 {
                                selection + 1
                            } else {
                                0
                            });
                            refresh_ui();
                        } else if item_count > 0 {
                            scene.selection = Some(0);
                            refresh_ui();
                        }
                    } else if input.just_pressed(Button::Up) {
                        if let Some(selection) = scene.selection {
                            scene.selection = Some(if selection > 0 {
                                selection - 1
                            } else {
                                item_count - 1
                            });
                            refresh_ui();
                        } else if item_count > 0 {
                            scene.selection = Some(item_count - 1);
                            refresh_ui();
                        }
                    }

                    // Use the selected item.
                    if players[player_id].is_alive() && input.just_pressed(Button::B) {
                        if let Some(selection) = scene.selection {
                            let item = &mut inventory.items[selection];
                            if InventoryItem::is_wearable(item.item_type) {
                                // Equip or unequip wearable.
                                if item.worn_by == Some(player_id) {
                                    item.unequip(players);
                                } else {
                                    item.equip(players, player_id);
                                }
                                refresh_ui();
                            }
                        }
                    }
                }
            }
        }
    }
}
