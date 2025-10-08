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

use std::cmp::min;
use std::path::Path;

use log::*;
use tiled::Loader;
use tiled::PropertyValue;

use crate::filepath_to_module_name;
use crate::tileset::SubSpriteData;
use crate::tileset::TilesetSpriteParameters;
use crate::Converter;
use crate::PaletteID;

#[derive(serde_derive::Serialize)]
pub(crate) struct Frame {
    tile_offset: usize,
    duration: usize,
}

#[derive(serde_derive::Serialize)]
pub(crate) struct AnimationDefinition {
    name: String,
    loops: bool,
    frames: Vec<Frame>,
}

#[derive(serde_derive::Serialize)]
pub(crate) struct SpriteSerializationData {
    // The total dimension of the sub-sprites, in tiles
    width: usize,
    height: usize,

    // Sub-sprites and their dimensions
    // (up to the sizes the Mega Drive supports)
    sprites: Vec<SubSpriteData>,

    animation_definitions: Vec<AnimationDefinition>,

    tileset: String,
    tiles_idx: usize,
}

/// Convert map to rust code. Returns the name of the tileset used.
pub(crate) fn convert_sprite(
    converter: &mut Converter,
    tsx_file: impl AsRef<Path>,
    output_file: impl AsRef<Path>,
    palette_id: &PaletteID,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut loader = Loader::new();
    let tileset = loader.load_tsx_tileset(&tsx_file)?;
    let sprites_per_column = (tileset.tilecount / tileset.columns) as usize;
    let sprites_per_row = tileset.columns as usize;
    let sprite_width = tileset.tile_width as usize / 8;
    let sprite_height = tileset.tile_height as usize / 8;

    debug!(
        "Converting sprite, tilecount={} columns={} sprites_per_row={}",
        tileset.tilecount, tileset.columns, sprites_per_row
    );

    // Split the sprite into smaller sprites supported by the
    // mega drive (at most 4x4).
    let mut sub_sprites = Vec::new();
    let mut tile_offset = 0;
    for x in 0..(sprite_width + 3) / 4 {
        for y in 0..(sprite_height + 3) / 4 {
            let tile_x = x * 4;
            let tile_y = y * 4;
            let tile_width = min(4, sprite_width - tile_x);
            let tile_height = min(4, sprite_height - tile_y);
            sub_sprites.push(SubSpriteData {
                x: tile_x * 8,
                y: tile_y * 8,
                width: tile_width,
                height: tile_height,
                tile_offset,
            });
            tile_offset += tile_width * tile_height;
        }
    }

    let tileset_name = filepath_to_module_name(&tileset.source);
    let tileset_idx = match converter.tileset_id(&tileset_name) {
        Some(x) => x,
        None => {
            let mut output_dir = converter.output_directory.clone();
            output_dir.push("tileset");
            let tileset = converter.convert_tileset(
                &tsx_file,
                palette_id,
                Some(TilesetSpriteParameters {
                    sprites_per_row,
                    sprites_per_column,
                    sub_sprites: sub_sprites.clone(),
                }),
            )?;
            converter.register_tileset(&tileset);
            debug!("Tileset {} registered", &tileset);
            assert!(tileset == tileset_name);
            converter.tileset_id(&tileset_name).unwrap()
        }
    };

    debug!(
        "Tileset contains {}x{} sprites",
        sprites_per_row, sprites_per_column
    );


    let mut sprite_data = SpriteSerializationData {
        width: sprite_width,
        height: sprite_height,
        sprites: sub_sprites,
        animation_definitions: Vec::new(),
        tileset: tileset_name.clone(),
        tiles_idx: tileset_idx,
    };

    for (_id, tile) in tileset.tiles() {
        let mut animation: Option<String> = None;
        let mut do_loop = false;
        if tile.properties.contains_key("animation") {
            if let PropertyValue::StringValue(s) = tile.properties.get("animation").unwrap() {
                animation = Some(s.to_string());
            } else {
                panic!("animation has unexpected value type");
            }
        }
        if tile.properties.contains_key("loop") {
            if let PropertyValue::BoolValue(b) = tile.properties.get("loop").unwrap() {
                do_loop = *b;
            } else {
                panic!("animation has unexpected value type");
            }
        }

        if tile.probability != 1.0 {
            warn!(
                "Note: Probabilities != 1.0 are not supported (set to {})",
                tile.probability
            );
        }

        if tile.user_type.is_some() {
            panic!("User types currently not supported");
        }
        if animation.is_some() {
            let mut definition = AnimationDefinition {
                name: crate::to_rust_enum_identifier(&animation.unwrap()),
                loops: do_loop,
                frames: Vec::new(),
            };
            if let Some(anim) = tile.animation.as_ref() {
                for frame in anim {
                    definition.frames.push(Frame {
                        tile_offset: frame.tile_id as usize
                            * sprite_data.width
                            * sprite_data.height,
                        duration: frame.duration as usize * 60 / 1000,
                    });
                }
            }
            sprite_data.animation_definitions.push(definition);
        }
    }
    sprite_data
        .animation_definitions
        .sort_by(|a, b| a.name.cmp(&b.name));
    let source = include_str!("../templates/sprite.rs");
    let handlebars = handlebars::Handlebars::new();
    let rendered = handlebars.render_template(source, &sprite_data).unwrap();

    std::fs::write(output_file, rendered)?;
    Ok(())
}
