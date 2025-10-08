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

use std::collections::HashSet;
use std::path::Path;

use log::*;
use tiled::LayerType;
use tiled::Loader;
use tiled::PropertyValue;
use tiled::TileLayer;

use crate::filepath_to_module_name;
use crate::Converter;
use crate::Layer;
use crate::PaletteID;
use crate::World;

#[derive(serde_derive::Serialize)]
pub struct EnemyData {
    kind: String,
    id: u16,
    x: u16,
    y: u16,
    properties: EnemyProperties,
}

#[derive(serde_derive::Serialize)]
pub struct NpcData {
    kind: String,
    dialogue_id: u16,
    x: u16,
    y: u16,
}

#[derive(serde_derive::Serialize)]
pub struct ItemData {
    kind: String,
    id: u16,
    x: u16,
    y: u16,
}

#[derive(serde_derive::Serialize)]
pub struct DoorData {
    id: u16,
    orientation: String,
    x: u16,
    y: u16,
}

#[derive(serde_derive::Serialize)]
pub struct SwitchData {
    id: u16,
    /// Index of the event that triggers when all map switches are pressed.
    /// Should be the same for switches on the same map.
    event_id: u16,
    x: u16,
    y: u16,
}

/// Enemy properties parsed from the map that can override the
/// default properties.
#[derive(serde_derive::Serialize)]
pub struct EnemyProperties {
    walk_data: Vec<WalkData>,
    speed: Option<i32>,
    health: Option<i32>,
    strength: Option<i32>,
    invulnerable: bool,
    flags: Option<i32>,
}

#[derive(serde_derive::Serialize)]
pub struct MapSerializationData {
    tileset_name: String,

    width: usize,  // Width in tiles
    height: usize, // Height in tiles
    gfx_layer: Vec<u16>,
    attr_layer: Vec<u16>,

    player_spawn_position: Option<(i16, i16)>,

    enemies: Vec<EnemyData>,
    npcs: Vec<NpcData>,
    items: Vec<ItemData>,
    doors: Vec<DoorData>,
    switches: Vec<SwitchData>,

    tiles_idx: usize,
}

pub struct ConvertMapResult {
    pub(crate) tileset: String,
    pub(crate) spawn_position: Option<(i16, i16)>,
    pub(crate) enemy_types: HashSet<String>,
    pub(crate) npc_types: HashSet<String>,
    pub(crate) item_types: HashSet<String>,
}

#[derive(serde_derive::Serialize)]
struct WalkData {
    command: String,
    duration: usize,
}

fn convert_walk_data(commands: &str) -> Vec<WalkData> {
    let mut rv = Vec::new();

    for token in commands.split(",") {
        let command = match token
            .chars()
            .next()
            .expect("Invalid formatted walk data: {commands}")
        {
            'U' => "Up",
            'D' => "Down",
            'L' => "Left",
            'R' => "Right",
            'P' => "Pause",
            _ => panic!("Invalid walk command: {token}"),
        };
        let duration = token.chars().skip(1).collect::<String>();
        let duration = duration.parse::<usize>();
        rv.push(WalkData {
            command: command.to_string(),
            duration: duration.expect("Invalid duration in walk command {token}"),
        });
    }

    rv
}

/// Convert map to rust code. Returns the name of the tileset used.
pub(crate) fn convert_map(
    converter: &mut Converter,
    tmx_file: impl AsRef<Path>,
    output_file: impl AsRef<Path>,
    world: &mut World,
    palette_id: &PaletteID,
) -> Result<ConvertMapResult, Box<dyn std::error::Error>> {
    let handlebars = handlebars::Handlebars::new();
    let mut loader = Loader::new();

    let mut enemy_types = HashSet::new();
    let mut npc_types = HashSet::new();
    let mut item_types = HashSet::new();
    let mut switch_event_id = None;

    let map = loader.load_tmx_map(&tmx_file)?;
    assert_eq!(map.orientation, tiled::Orientation::Orthogonal);

    let mut attribute_layer = Layer::<u16>::new(
        map.width.try_into().unwrap(),
        map.height.try_into().unwrap(),
    );

    let mut gfx_layer = Layer::<u16>::new(
        map.width.try_into().unwrap(),
        map.height.try_into().unwrap(),
    );

    let mut map_serialization_data = MapSerializationData {
        tileset_name: "".to_string(),
        width: map.width.try_into().unwrap(),
        height: map.height.try_into().unwrap(),
        gfx_layer: Vec::new(),
        attr_layer: Vec::new(),
        player_spawn_position: None,
        enemies: Vec::new(),
        npcs: Vec::new(),
        items: Vec::new(),
        doors: Vec::new(),
        switches: Vec::new(),

        tiles_idx: 0,
    };

    if map.tilesets().len() != 1 {
        panic!("Must have exactly one tileset per map");
    }

    map_serialization_data.tileset_name = filepath_to_module_name(&map.tilesets()[0].source);
    map_serialization_data.tiles_idx = match converter
        .tileset_id(&map_serialization_data.tileset_name)
    {
        Some(id) => id,
        None => {
            let mut output_dir = converter.output_directory.clone();
            output_dir.push("tileset");
            let tileset = converter.convert_tileset(&map.tilesets()[0].source, palette_id, None)?;
            converter.register_tileset(&tileset);
            debug!("Tileset {} registered", &tileset);
            assert!(tileset == map_serialization_data.tileset_name);
            converter.tileset_id(&tileset).unwrap()
        }
    };

    // Merge attributes to one layer.
    // Only one attribute can be present for each tile.
    for layer in map.layers() {
        assert_eq!(layer.offset_x, 0.0f32);
        assert_eq!(layer.offset_y, 0.0f32);

        if layer.name == "gfx" {
            let LayerType::Tiles(TileLayer::Finite(tiles)) = layer.layer_type() else {
                panic!("Unexpected gfx layer type");
            };
            for x in 0..tiles.width() {
                for y in 0..tiles.height() {
                    gfx_layer.set(
                        x.try_into().unwrap(),
                        y.try_into().unwrap(),
                        tiles
                            .get_tile_data(x.try_into().unwrap(), y.try_into().unwrap())
                            .map(|tile| tile.id() + 1)
                            .unwrap_or(0)
                            .try_into()
                            .unwrap(),
                    );
                }
            }
            continue;
        }

        let attribute_index = resources::MapTileAttribute::try_from(layer.name.as_ref());

        if layer.name != "objs" && !attribute_index.is_ok() {
            warn!("Warning: Unknown layer type {}, skipping", layer.name);
            continue;
        };

        match layer.layer_type() {
            LayerType::Tiles(TileLayer::Finite(tiles)) => {
                assert_eq!(tiles.width(), map.width);
                assert_eq!(tiles.height(), map.height);
                for x in 0..tiles.width() {
                    for y in 0..tiles.height() {
                        if let Some(_) =
                            tiles.get_tile(i32::try_from(x).unwrap(), i32::try_from(y).unwrap())
                        {
                            let prev = attribute_layer.set(
                                x.try_into().unwrap(),
                                y.try_into().unwrap(),
                                attribute_index.expect("Already checked before").bits(),
                            );
                            if prev.is_none() {
                                panic!("This should not happen as we've verified layer sizes?");
                            }
                            if prev.unwrap() != 0 {
                                panic!(
                                    "Multiple attributes specified for one tile (in {:?} at x: {x}, y: {y}), this is unsupported.", tmx_file.as_ref()
                                );
                            }
                        }
                    }
                }
            }
            LayerType::Objects(objects) => {
                for obj in objects.objects() {
                    debug!("Handling object {:?}", *obj);
                    if obj.name == "Spawn" {
                        map_serialization_data.player_spawn_position =
                            Some((obj.x.round() as i16, obj.y.round() as i16));
                    } else if obj.user_type == "Enemy" {
                        // Only one of each miniboss type is allowed.
                        if obj.name.contains("Miniboss") && enemy_types.contains(&obj.name) {
                            panic!("multiple instances of miniboss {}", obj.name);
                        }
                        enemy_types.insert(obj.name.clone());
                        let mut walk_data = Vec::new();
                        if obj.properties.contains_key("walk") {
                            if let PropertyValue::StringValue(s) =
                                obj.properties.get("walk").unwrap()
                            {
                                walk_data = convert_walk_data(s);
                            } else {
                                panic!("walk has unexpected value type");
                            }
                        }
                        let maybe_get_int_property = |name| {
                            if !obj.properties.contains_key(name) {
                                return None;
                            }
                            if let PropertyValue::IntValue(i) = obj.properties.get(name).unwrap() {
                                Some(*i)
                            } else {
                                panic!("{name} has unexpected value type");
                            }
                        };
                        let get_bool_property = |name| {
                            if !obj.properties.contains_key(name) {
                                return false;
                            }
                            if let PropertyValue::BoolValue(b) = obj.properties.get(name).unwrap() {
                                *b
                            } else {
                                panic!("{name} has unexpected value type");
                            }
                        };
                        let properties = EnemyProperties {
                            walk_data,
                            speed: maybe_get_int_property("speed"),
                            health: maybe_get_int_property("health"),
                            strength: maybe_get_int_property("strength"),
                            invulnerable: get_bool_property("invulnerable"),
                            flags: maybe_get_int_property("flags"),
                        };

                        map_serialization_data.enemies.push(EnemyData {
                            kind: obj.name.to_string(),
                            id: world.next_enemy_id(),
                            x: obj.x.round() as u16,
                            y: obj.y.round() as u16,
                            properties,
                        });
                    } else if obj.user_type == "Npc" {
                        let dialogue_id = if let PropertyValue::IntValue(i) =
                            obj.properties.get("dialogue_id").unwrap()
                        {
                            *i
                        } else {
                            panic!("dialogue_id has unexpected value type");
                        };
                        map_serialization_data.npcs.push(NpcData {
                            kind: obj.name.to_string(),
                            dialogue_id: dialogue_id as u16,
                            x: obj.x.round() as u16,
                            y: obj.y.round() as u16,
                        });
                        npc_types.insert(obj.name.clone());
                    } else if obj.user_type == "Item" {
                        map_serialization_data.items.push(ItemData {
                            kind: obj.name.to_string(),
                            id: world.next_item_id(),
                            x: obj.x.round() as u16,
                            y: obj.y.round() as u16,
                        });
                        item_types.insert(obj.name.clone());
                    } else if obj.user_type == "Door" {
                        map_serialization_data.doors.push(DoorData {
                            id: world.next_door_id(),
                            orientation: if obj.name.ends_with("H") {
                                "Horizontal".to_string()
                            } else if obj.name.ends_with("V") {
                                "Vertical".to_string()
                            } else {
                                panic!("Invalid door orientation: {}", obj.name)
                            },
                            x: obj.x.round() as u16,
                            y: obj.y.round() as u16,
                        });
                    } else if obj.user_type == "Switch" {
                        let event_id = if let PropertyValue::IntValue(i) =
                            obj.properties.get("event_id").unwrap()
                        {
                            *i
                        } else {
                            panic!("event_id has unexpected value type");
                        };
                        if let Some(switch_event_id) = switch_event_id {
                            if switch_event_id != event_id {
                                panic!(
                                    "map with multiple switch event IDs found ({}, {})",
                                    switch_event_id, event_id
                                );
                            }
                        }
                        switch_event_id = Some(event_id);
                        map_serialization_data.switches.push(SwitchData {
                            id: world.next_switch_id(),
                            event_id: event_id as u16,
                            x: obj.x.round() as u16,
                            y: obj.y.round() as u16,
                        });
                    }
                }
            }
            _ => panic!("Only finite tiles and object layer types are supported"),
        }
    }

    let source = include_str!("../templates/map_source.rs");
    map_serialization_data.gfx_layer = gfx_layer.data;
    map_serialization_data.attr_layer = attribute_layer.data;
    let rendered = handlebars
        .render_template(source, &map_serialization_data)
        .unwrap();

    std::fs::write(output_file, rendered)?;

    Ok(ConvertMapResult {
        tileset: map_serialization_data.tileset_name,
        spawn_position: map_serialization_data.player_spawn_position,
        enemy_types,
        npc_types,
        item_types,
    })
}
