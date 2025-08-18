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

use log::*;
mod image;
mod map;
mod sprite;
mod tileset;
mod world;

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;

use map::convert_map;
use sprite::convert_sprite;
use tileset::convert_tileset;
use tileset::TilesetSpriteParameters;
pub use world::World;

/// Converts a filename to an identifier.
pub fn filepath_to_module_name(path: impl AsRef<Path>) -> String {
    path.as_ref()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .split(".")
        .next()
        .unwrap()
        .to_string()
        .replace("-", "_")
}

/// Converts an enum name to a module path (e.g. BlueSoldier -> blue_soldier)
pub fn enum_to_module_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_uppercase() {
                "_".to_string() + &c.to_string()
            } else {
                c.to_string()
            }
        })
        .collect::<String>()[1..]
        .to_string()
}

pub fn to_rust_enum_identifier(name: &String) -> String {
    let mut rv = String::new();
    let mut make_upper = true;
    for c in name.chars() {
        if make_upper {
            rv.push_str(&c.to_uppercase().to_string());
            make_upper = false;
        } else if c == '-' {
            make_upper = true;
            continue;
        } else {
            rv.push(c);
        }
    }
    rv
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Rgba {
    r: u8,
    g: u8,
    b: u8,
    a: u8,
}

impl Rgba {
    /// Converts the RGBA color to a 16 bit RGB444 value that can be loaded into genesis palette
    /// VRAM.
    ///
    /// Note: The alpha channel is not encoded, this must be handled differently due to hardware
    ///       limitations.
    pub fn to_rgb444(self) -> u16 {
        (u16::from(self.b) & 0xF0) << 4 | u16::from(self.g) & 0xF0 | u16::from(self.r) >> 4
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct Palette {
    // Option to indicate that some indices are not used
    colors: [Option<u16>; 16],
    colors_rgba: [Option<Rgba>; 16],
}

/// Palette ID that is unique to a specific location.
#[derive(Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct PaletteID {
    id: GamePalette,
    /// The applicable world (e.g. "water-temple").
    /// Global if not set.
    world: Option<String>,
}

/// In-game palettes and their use cases.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub enum GamePalette {
    /// Palette of the player characters
    Player = 0,
    /// Palette of UI elements like health, inventory, dialogues
    UI,
    /// Palette of all enemies. This is world-specific
    Enemy,
    /// Palette of the world background and tiles. This is world-specific
    Background,
}

impl GamePalette {
    pub fn for_world(self, world: &str) -> PaletteID {
        PaletteID {
            id: self,
            world: Some(world.to_string()),
        }
    }

    pub fn global(self) -> PaletteID {
        PaletteID {
            id: self,
            world: None,
        }
    }
}

impl From<GamePalette> for char {
    fn from(value: GamePalette) -> Self {
        match value {
            GamePalette::Player => 'A',
            GamePalette::UI => 'B',
            GamePalette::Background => 'C',
            GamePalette::Enemy => 'D',
        }
    }
}

/// Represents a map layer, used to merge attribute (i.e non-gfx) layers.
pub struct Layer<T> {
    pub width: usize,
    pub height: usize,
    pub data: Vec<T>,
}

impl<T: Copy + Clone + Default> Layer<T> {
    pub fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            data: vec![T::default(); width * height],
        }
    }

    // Sets a new value in the Layer, returns previous value.
    // Returns None if out of bound.
    pub fn set(&mut self, x: usize, y: usize, val: T) -> Option<T> {
        if x >= self.width || y >= self.height {
            None
        } else {
            let idx = x + y * self.width;
            let prev = self.data[idx];
            self.data[idx] = val;
            Some(prev)
        }
    }
}

#[derive(serde_derive::Serialize, Default)]
pub(crate) struct PaletteData {
    // Palettes that are the same throughout the game.
    // Using a tree map to keep them sorted by palette ID.
    global_palettes: BTreeMap<char, [u16; 16]>,

    // Palettes that change depending on the loaded world.
    world_palettes: BTreeMap<char, BTreeMap<String, [u16; 16]>>,
}

#[derive(serde_derive::Serialize, Default)]
pub(crate) struct SpriteModData {
    sprites: Vec<String>,
}

#[derive(serde_derive::Serialize, Default)]
pub(crate) struct TilesetModData {
    tilesets: Vec<String>,
    tilesets_count: usize,
}

#[derive(serde_derive::Serialize, Default)]
pub(crate) struct ImageModData {
    images: Vec<String>,
}

#[derive(serde_derive::Serialize, Default)]
pub(crate) struct MapModData {
    world: Vec<(String, String)>,
}

#[derive(serde_derive::Serialize)]
pub(crate) struct Enemy {
    name: String,
    // Lowercase `name` / no dashes etc so that it is a valid rust module name.
    module: String,
    // Enum value of the enemy type.
    value: u16,
}

#[derive(serde_derive::Serialize, Default)]
pub(crate) struct EnemiesData {
    // The possible list of enemy types. Populated based on the enemy names
    // seen on various maps.
    enemies: Vec<Enemy>,
}

#[derive(serde_derive::Serialize)]
// Data used to serialize entities with named types.
pub(crate) struct Entity {
    name: String,
    // Lowercase `name` / no dashes etc so that it is a valid rust module name.
    module: String,
}

/// Try to combine two palettes so that multiple tilesets can share the same palette.
///
/// Returns updated palette + image data if feasible.
pub(crate) fn try_apply_existing_palette(
    existing_palette: &Palette,
    image_palette: &Palette,
    image_data: &[u8],
) -> Result<(Palette, Vec<u8>), Box<dyn std::error::Error>> {
    let mut image = image_data.to_vec();
    let mut palette = existing_palette.clone();
    let mut image_palette = image_palette.clone();

    // Remove colors that aren't actually used by the image.
    let mut color_used = vec![false; image_palette.colors_rgba.len()];
    for b in image.iter() {
        for idx in [b & 0xf, (b & 0xf0 >> 4)] {
            color_used[idx as usize] = true
        }
    }
    for idx in 0..image_palette.colors.len() {
        if !color_used[idx] {
            image_palette.colors[idx] = None;
            image_palette.colors_rgba[idx] = None;
        }
    }

    // If palette is undefined, just take the initial one.
    if palette.colors_rgba.iter().skip(1).all(|c| c.is_none()) {
        return Ok((image_palette, image));
    }

    info!("Combining with existing palette");

    let mut indices_to_remap = [0; 16];

    // Color 0 is always transparent and already taken care of by the image loading
    // process.
    for (idx, color) in image_palette.colors.iter().skip(1).enumerate() {
        if color.is_none() {
            continue;
        }
        let color_rgba = image_palette.colors_rgba[idx + 1];

        // Check if the color is already existing in the previous palette.
        if let Some(existing_idx) = palette
            .colors_rgba
            .iter()
            .skip(1)
            .position(|c| *c == color_rgba)
        {
            if existing_idx == idx {
                // It exists and is at the same index, nothing to do.
                continue;
            }

            // Otherwise we need to update the image data to use the correct index.
            indices_to_remap[idx + 1] = existing_idx + 1;
        } else {
            // Color not present at all in the previous palette, need to insert the new
            // color.
            if let Some(next_available) =
                palette.colors_rgba.iter().skip(1).position(|c| c.is_none())
            {
                palette.colors[next_available + 1] = *color;
                palette.colors_rgba[next_available + 1] = color_rgba;
                if next_available != idx {
                    indices_to_remap[idx + 1] = next_available + 1;
                }
            } else {
                panic!("No available free slot in palette to fit color");
            }
        }
    }

    // Update image nibbles if necessary.
    let update_indices = |val: u8| -> u8 {
        let v = indices_to_remap[val as usize];
        if v > 0 {
            v as u8
        } else {
            val
        }
    };
    let update_indices_nibbles = |val: u8| -> u8 {
        let v1 = val & 0x0F;
        let v2 = val & 0xF0;

        update_indices(v1) | (update_indices(v2 >> 4) << 4)
    };

    for b in image.iter_mut() {
        *b = update_indices_nibbles(*b);
    }

    Ok((palette, image))
}

// We want a global struct tracking
// - Which tilesets are used (load on demand)
// - Which palettes are used
//
// Finally, the output should be assigned fixed memory addresses
// and only be accessible via something like this:
// fn load_from_memory<T>(addr: usize) -> T;

/// Tracks global state across all sprites + maps.
pub struct Converter {
    output_directory: PathBuf,

    palettes: HashMap<PaletteID, Palette>,
    tilesets: Vec<String>,
    images: Vec<String>,
    sprites: HashSet<String>,
    world: HashSet<String>,
    enemy_types: HashSet<String>,
    npc_types: HashSet<String>,
    item_types: HashSet<String>,
}

impl Converter {
    pub fn new(output_directory: impl AsRef<Path>) -> Self {
        Self {
            output_directory: PathBuf::from(output_directory.as_ref()),
            palettes: HashMap::new(),
            tilesets: Vec::new(),
            images: Vec::new(),
            sprites: HashSet::new(),
            world: HashSet::new(),
            enemy_types: HashSet::new(),
            npc_types: HashSet::new(),
            item_types: HashSet::new(),
        }
    }

    pub(crate) fn output_directory(&self) -> &Path {
        self.output_directory.as_ref()
    }

    pub(crate) fn register_tileset(&mut self, tileset: impl Into<String>) {
        let tileset = tileset.into();
        info!("Registering tileset {tileset:?}");
        assert!(self.tileset_id(&tileset).is_none());
        self.tilesets.push(tileset);
    }

    pub fn tileset_id(&self, tileset: &str) -> Option<usize> {
        self.tilesets
            .iter()
            .enumerate()
            .find(|(_, v)| *v == tileset)
            .map(|(i, _)| i)
    }

    pub(crate) fn convert_tileset(
        &mut self,
        tsx_file: impl AsRef<Path>,
        palette_idx: &PaletteID,
        parameters: Option<TilesetSpriteParameters>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let tsx_file = tsx_file.as_ref();
        let mut output_dir = self.output_directory.clone();
        output_dir.push("tileset");
        info!("Converting tileset {tsx_file:?} -> target dir: {output_dir:?}");

        if !self.palettes.contains_key(palette_idx) {
            self.palettes
                .insert(palette_idx.clone(), Default::default());
            debug!("Loading new palette");
        };

        let palette_data = self.palettes.get_mut(palette_idx).unwrap();
        let tileset = convert_tileset(
            tsx_file,
            output_dir,
            palette_idx.id,
            palette_data,
            parameters,
        )?;
        Ok(tileset)
    }

    pub(crate) fn convert_map(
        &mut self,
        tmx_file: impl AsRef<Path>,
        output_file: impl AsRef<Path>,
        world: &mut World,
        palette_id: &PaletteID,
    ) -> Result<map::ConvertMapResult, Box<dyn std::error::Error>> {
        let tmx_file = tmx_file.as_ref();
        let output_file = output_file.as_ref();
        info!("Converting {tmx_file:?} -> {output_file:?}");
        let res = convert_map(self, tmx_file, output_file, world, palette_id)?;
        if !self.tilesets.contains(&res.tileset) {
            panic!("Tileset '{}' not registered.", res.tileset);
        }
        for typ in res.enemy_types.iter() {
            if typ.contains("Miniboss") && self.enemy_types.contains(typ) {
                panic!("multiple instances of miniboss {}", typ);
            }
            self.enemy_types.insert(typ.clone());
        }
        for typ in res.npc_types.iter() {
            self.npc_types.insert(typ.clone());
        }
        for typ in res.item_types.iter() {
            self.item_types.insert(typ.clone());
        }
        Ok(res)
    }

    pub fn convert_world(&mut self, details: &World) -> Result<(), Box<dyn std::error::Error>> {
        world::convert_world(self, details)?;
        self.world.insert(details.identifier.clone());
        Ok(())
    }

    pub fn convert_sprite(
        &mut self,
        tsx_file: impl AsRef<Path>,
        palette_id: &PaletteID,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let tsx_file = tsx_file.as_ref();

        let identifier = filepath_to_module_name(tsx_file);
        let mut output_file = self.output_directory.clone();
        output_file.push("sprites");
        std::fs::create_dir_all(&output_file)?;
        output_file.push(format!("{}.rs", identifier));

        info!("Converting {tsx_file:?} -> {output_file:?}");

        let sprite_name = filepath_to_module_name(&tsx_file);
        convert_sprite(self, &tsx_file, output_file, palette_id)?;

        debug!("Converted sprite to {sprite_name}");
        if !self.sprites.insert(sprite_name) {
            panic!("Multiple sprites with the same filename are unsupported");
        }
        Ok(())
    }

    /// Register image to later write as image mod
    pub(crate) fn register_image(&mut self, image: impl Into<String>) {
        let image = image.into();
        info!("Registering image {image:?}");
        self.images.push(filepath_to_module_name(&image));
    }

    pub fn convert_image(
        &mut self,
        png_file: impl AsRef<Path>,
        palette_id: &PaletteID,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let png_file = png_file.as_ref();
        let mut images_dir = self.output_directory.clone();
        images_dir.push("images");
        std::fs::create_dir_all(&images_dir)?;
        info!("Converting image {png_file:?} -> target dir: {images_dir:?}");

        let mut tileset_dir = self.output_directory.clone();
        tileset_dir.push("tileset");
        std::fs::create_dir_all(&tileset_dir)?;
        if !self.palettes.contains_key(palette_id) {
            self.palettes.insert(palette_id.clone(), Default::default());
            debug!("Loading new palette");
        };
        let img_name = filepath_to_module_name(png_file.file_stem().unwrap().to_str().unwrap());
        self.register_image(&img_name);
        self.register_tileset(&img_name);
        let tileset_id = self.tileset_id(&img_name).unwrap();
        let palette_data = self.palettes.get_mut(palette_id).unwrap();
        image::convert_image(
            png_file,
            images_dir,
            tileset_dir,
            tileset_id,
            palette_id,
            palette_data,
        )?;
        Ok(())
    }

    pub fn write_palettes(
        &self,
        output_file: impl AsRef<Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let handlebars = handlebars::Handlebars::new();
        let source = include_str!("../templates/palette.rs");

        let mut palette_data = PaletteData::default();
        palette_data.global_palettes = BTreeMap::new();
        palette_data.world_palettes = BTreeMap::new();
        for (key, palette) in self.palettes.iter() {
            let mut raw_palette = [0u16; 16];
            for color in 0..16 {
                raw_palette[color] = palette.colors[color].unwrap_or(0);
            }

            if let Some(world) = &key.world {
                if !palette_data
                    .world_palettes
                    .contains_key(&char::from(key.id))
                {
                    palette_data
                        .world_palettes
                        .insert(char::from(key.id), BTreeMap::new());
                }
                palette_data
                    .world_palettes
                    .get_mut(&char::from(key.id))
                    .unwrap()
                    .insert(to_rust_enum_identifier(&world), raw_palette);
            } else {
                palette_data
                    .global_palettes
                    .insert(char::from(key.id), raw_palette);
            }
        }
        let rendered = handlebars.render_template(source, &palette_data).unwrap();

        std::fs::write(output_file, rendered)?;
        Ok(())
    }

    pub fn write_sprite_mod(
        &self,
        output_file: impl AsRef<Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let handlebars = handlebars::Handlebars::new();
        let source = include_str!("../templates/sprite_mod.rs");

        let mut sprite_mod_data = SpriteModData::default();

        sprite_mod_data.sprites = self.sprites.iter().cloned().collect::<Vec<_>>();

        let rendered = handlebars
            .render_template(source, &sprite_mod_data)
            .unwrap();

        std::fs::write(output_file, rendered)?;
        Ok(())
    }

    pub fn write_tilesets_mod(
        &self,
        output_file: impl AsRef<Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let handlebars = handlebars::Handlebars::new();
        let source = include_str!("../templates/tileset_mod.rs");

        let mut tileset_mod_data = TilesetModData::default();

        tileset_mod_data.tilesets = self.tilesets.iter().cloned().collect::<Vec<_>>();
        tileset_mod_data.tilesets_count = tileset_mod_data.tilesets.len();

        let rendered = handlebars
            .render_template(source, &tileset_mod_data)
            .unwrap();

        std::fs::write(output_file, rendered)?;
        Ok(())
    }

    pub fn write_image_mod(
        &self,
        output_file: impl AsRef<Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let handlebars = handlebars::Handlebars::new();
        let source = include_str!("../templates/image_mod.rs");

        let mut image_mod_data = ImageModData::default();

        image_mod_data.images = self.images.iter().cloned().collect::<Vec<_>>();

        let rendered = handlebars.render_template(source, &image_mod_data).unwrap();

        std::fs::write(output_file, rendered)?;
        Ok(())
    }

    pub fn write_map_mod(
        &self,
        output_file: impl AsRef<Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let handlebars = handlebars::Handlebars::new();
        let source = include_str!("../templates/map_mod.rs");

        let mut tileset_mod_data = MapModData::default();

        tileset_mod_data.world = self
            .world
            .iter()
            .map(|x| {
                (
                    filepath_to_module_name(Path::new(x)),
                    to_rust_enum_identifier(x),
                )
            })
            .collect::<Vec<_>>();

        let rendered = handlebars
            .render_template(source, &tileset_mod_data)
            .unwrap();

        std::fs::write(output_file, rendered)?;
        Ok(())
    }

    pub fn write_main_mod(
        &self,
        output_file: impl AsRef<Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        std::fs::write(
            output_file,
            "pub mod maps;
pub mod palettes;
pub mod sprites;
pub mod enemies;
pub mod npcs;
pub mod items;
pub mod tileset;
pub mod images;",
        )?;
        Ok(())
    }

    pub fn write_enemies(
        &self,
        output_file: impl AsRef<Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let handlebars = handlebars::Handlebars::new();
        let source = include_str!("../templates/enemies.rs");

        let mut enemies_data = EnemiesData::default();
        enemies_data.enemies = self
            .enemy_types
            .clone()
            .iter()
            .enumerate()
            .map(|(index, name)| Enemy {
                name: name.to_string(),
                module: enum_to_module_name(name).to_lowercase(),
                // Enemy type enum values are used in bitmasks.
                value: (1 << index) as u16,
            })
            .collect();

        let rendered = handlebars.render_template(source, &enemies_data).unwrap();

        std::fs::write(output_file, rendered)?;
        Ok(())
    }

    pub fn write_npcs(
        &self,
        output_file: impl AsRef<Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let handlebars = handlebars::Handlebars::new();
        let source = include_str!("../templates/npcs.rs");

        let npcs: Vec<Entity> = self
            .npc_types
            .clone()
            .iter()
            .map(|name| Entity {
                name: name.to_string(),
                module: enum_to_module_name(name).to_lowercase(),
            })
            .collect();

        let rendered = handlebars.render_template(source, &npcs).unwrap();

        std::fs::write(output_file, rendered)?;
        Ok(())
    }

    pub fn write_items(
        &self,
        output_file: impl AsRef<Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let handlebars = handlebars::Handlebars::new();
        let source = include_str!("../templates/items.rs");

        let items: Vec<Entity> = self
            .item_types
            .clone()
            .iter()
            .map(|name| Entity {
                name: name.to_string(),
                module: enum_to_module_name(name).to_lowercase(),
            })
            .collect();

        let rendered = handlebars.render_template(source, &items).unwrap();

        std::fs::write(output_file, rendered)?;
        Ok(())
    }
}
