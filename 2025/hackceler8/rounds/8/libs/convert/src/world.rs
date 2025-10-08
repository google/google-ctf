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

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use serde_derive::Deserialize;
use serde_derive::Serialize;
use serde_json;

use crate::GamePalette;

#[derive(Clone)]
pub struct World {
    // Path of the Tiled .world file
    pub path: PathBuf,

    /// Identifier of this world (also called "WorldType")
    pub identifier: String,

    /// Actual existing submaps.
    pub map_identifiers: Vec<Option<(String, i16, i16)>>,

    /// Width in maps.
    pub width: usize,
    /// Height in maps.
    pub height: usize,

    /// The initial map tile.
    pub spawn_pos: Option<(i16, i16)>,

    /// The next ID to use for objects found in this world's maps.
    next_enemy_id: u16,
    next_item_id: u16,
    next_door_id: u16,
    next_switch_id: u16,
}

impl World {
    pub fn next_enemy_id(&mut self) -> u16 {
        let id = self.next_enemy_id;
        self.next_enemy_id += 1;
        id
    }

    pub fn next_item_id(&mut self) -> u16 {
        assert!(
            self.next_item_id < 16,
            "Too many items in world {}, can only have 16",
            self.path.display(),
        );
        let id = self.next_item_id;
        self.next_item_id += 1;
        id
    }

    pub fn next_door_id(&mut self) -> u16 {
        assert!(
            self.next_door_id < 16,
            "Too many doors in world {}, can only have 16",
            self.path.display(),
        );
        let id = self.next_door_id;
        self.next_door_id += 1;
        id
    }

    pub fn next_switch_id(&mut self) -> u16 {
        assert!(
            self.next_switch_id < 16,
            "Too many switches in world {}, can only have 16",
            self.path.display(),
        );
        let id = self.next_switch_id;
        self.next_switch_id += 1;
        id
    }
}

#[derive(serde_derive::Serialize)]
pub(crate) struct WorldSerializationData {
    identifier: String,
    map_identifiers: Vec<Option<(String, i16, i16)>>,
    width: usize,
    height: usize,
    spawn_pos: Option<(i16, i16)>,
}

#[derive(Serialize, Deserialize, Debug)]
struct WorldJson {
    maps: Vec<MapJson>,
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct MapJson {
    file_name: String,
    width: usize,
    height: usize,
    x: i32,
    y: i32,
}

impl World {
    pub fn new(path: PathBuf, identifier: String) -> Result<World, Box<dyn std::error::Error>> {
        let mut world = World {
            path,
            identifier,
            map_identifiers: Vec::new(),
            width: 0,
            height: 0,
            spawn_pos: None,
            next_enemy_id: 0,
            next_item_id: 0,
            next_door_id: 0,
            next_switch_id: 0,
        };
        world.load_maps()?;
        Ok(world)
    }

    fn load_maps(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let world_file = File::open(&self.path)?;
        let world_data: WorldJson = serde_json::from_reader(BufReader::new(world_file))?;

        for map in world_data.maps.iter() {
            // Convert pos in tiles to pos in maps.
            let x = map.x as usize / 320;
            let y = map.y as usize / 224;

            self.width = self.width.max(x + 1);
            self.height = self.height.max(y + 1);
        }

        self.map_identifiers = vec![None; self.width * self.height];
        for map in world_data.maps.iter() {
            let x = map.x as usize / 320;
            let y = map.y as usize / 224;
            self.map_identifiers[x + y * self.width] = Some((
                map.file_name.strip_suffix(".tmx").unwrap().to_string(),
                x as i16,
                y as i16,
            ));
        }
        Ok(())
    }
}

pub(crate) fn convert_world(
    converter: &mut crate::Converter,
    world: &World,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut world = world.clone();
    let world_id = world.identifier.clone();
    for id in world.map_identifiers.clone() {
        if let Some(id) = id {
            let (m, x, y) = id;
            std::fs::create_dir_all(
                PathBuf::from(converter.output_directory())
                    .join("maps")
                    .join(world_id.replace("-", "_")),
            )
            .unwrap();
            let fout = PathBuf::from(converter.output_directory())
                .join("maps")
                .join(world_id.replace("-", "_"))
                .join(format!("{m}.rs"));

            // This is actually the input file..
            let file = PathBuf::from(&world.path.parent().unwrap()).join(format!("{m}.tmx"));
            let rv = converter.convert_map(
                &file,
                &fout,
                &mut world,
                &GamePalette::Background.for_world(&world_id),
            )?;
            if rv.spawn_position.is_some() {
                if world.spawn_pos.is_some() {
                    panic!("Multiple maps in world have a spawn position");
                }

                world.spawn_pos = Some((x, y));
            }
        }
    }

    let data = WorldSerializationData {
        identifier: world_id.clone(),
        map_identifiers: world.map_identifiers,
        width: world.width,
        height: world.height,
        spawn_pos: world.spawn_pos,
    };
    let source = include_str!("../templates/world_mod.rs");
    let handlebars = handlebars::Handlebars::new();
    let rendered = handlebars.render_template(source, &data).unwrap();

    std::fs::write(
        PathBuf::from(converter.output_directory())
            .join("maps")
            .join(world_id.replace("-", "_"))
            .join("mod.rs"),
        rendered,
    )?;
    Ok(())
}
