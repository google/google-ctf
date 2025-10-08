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
use std::path::Path;

use log::*;
use tiled::Loader;

use crate::filepath_to_module_name;
use crate::GamePalette;
use crate::Palette;
use crate::Rgba;

/// The color of the background and the screen border.
const BG_COLOR: Rgba = Rgba {
    r: 0,
    g: 0,
    b: 0,
    a: 255,
};

/// Extract palette and pixel indices from PNG, verifying parameters along the way.
///
/// The resulting vector contains the indices in its nibbles, i.e. 4 bits per pixel.
pub fn load_png(file: impl AsRef<Path> + std::fmt::Debug) -> std::io::Result<(Palette, Vec<u8>)> {
    let decoder = png::Decoder::new(File::open(&file)?);
    let mut reader = decoder.read_info()?;
    let info = reader.info();

    if info.width % 8 > 0 || info.height % 8 > 0 {
        panic!("Invalid dimensions for PNG");
    }

    let Some(palette) = &info.palette else {
        panic!("Image not in indexed mode");
    };

    if !matches!(info.bit_depth, png::BitDepth::One)
        && !matches!(info.bit_depth, png::BitDepth::Four)
        && !matches!(info.bit_depth, png::BitDepth::Eight)
    {
        panic!(
            "{file:?}: Support for bitdepth {:?} (!= 4 && != 8) not implemented",
            info.bit_depth
        );
    }

    // 3 bytes per color
    if palette.len() > 16 * 3 {
        panic!("Image uses too many colors");
    }
    debug!("Palette has {} colors", palette.len() / 3);

    if let Some(trns) = info.trns.as_ref() {
        debug!("Palette has alpha channel");
        // There must only be one transparent color and that one must be fully transparent.
        if trns.iter().any(|&b| b > 0 && b < 255) {
            panic!("Transparent pixels must either be fully transparent or fully opaque");
        }
        if trns.iter().filter(|&&b| b == 0).count() > 1 {
            panic!("There must only be exactly one fully transparent palette entry");
        }
    }

    // Convert palette to a 4 byte RGBA palette.
    let mut palette_rgba = vec![
        Rgba {
            r: 0,
            g: 0,
            b: 0,
            a: 0
        };
        palette.len() / 3
    ];
    for i in 0..palette.len() / 3 {
        palette_rgba[i].r = palette[i * 3];
        palette_rgba[i].g = palette[i * 3 + 1];
        palette_rgba[i].b = palette[i * 3 + 2];

        // Default to alpha=255.
        palette_rgba[i].a = info
            .trns
            .as_ref()
            .and_then(|b| b.get(i))
            .cloned()
            .unwrap_or(255);
    }

    let mut buf = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf)?;
    let mut bytes = buf[..info.buffer_size()].to_vec();

    if matches!(info.bit_depth, png::BitDepth::Eight) {
        // Change image data from 8 to 4 bits per pixel.
        let mut new_bytes = vec![0; bytes.len() / 2];
        for i in 0..new_bytes.len() {
            let b1 = bytes[i * 2];
            let b2 = bytes[i * 2 + 1];
            assert!(b1 < 16);
            assert!(b2 < 16);
            new_bytes[i] = (b1 << 4) + b2;
        }
        bytes = new_bytes;
    } else if matches!(info.bit_depth, png::BitDepth::One) {
        // Change image data from 1 to 4 bits per pixel.
        let mut new_bytes = vec![0; bytes.len() * 4];
        for i in 0..new_bytes.len() * 2 {
            let exp_src = 7 - i % 8;
            let exp_dst = 4 - (i % 2) * 4;
            let bit = (bytes[i / 8] & (1 << exp_src)) >> exp_src;
            new_bytes[i / 2] |= bit << exp_dst;
        }
        bytes = new_bytes;
    }

    // Determine if we have a transparent color and its index.
    // We already verified above that there can only be at most result here.
    let transparent_idx = palette_rgba
        .iter()
        .enumerate()
        .filter_map(|(idx, p)| if p.a == 0 { Some(idx) } else { None })
        .next();

    // If the transparent index is set and not the first one, update the image.
    let maybe_change = |val: u8, a: u8, b: u8| -> u8 {
        if val == a {
            b
        } else if val == b {
            a
        } else {
            val
        }
    };
    let maybe_change_nibbles = |val: u8, a: u8, b: u8| -> u8 {
        let v1 = val & 0x0F;
        let v2 = val & 0xF0;

        maybe_change(v1, a, b) | (maybe_change(v2 >> 4, a, b) << 4)
    };

    let mut palette = Palette::default();
    for (idx, p) in palette_rgba.iter().enumerate() {
        palette.colors[idx] = Some(p.to_rgb444());
        palette.colors_rgba[idx] = Some(*p);
    }

    if let Some(transparent_idx) = transparent_idx {
        if transparent_idx > 0 {
            debug!("Transparent index is not 0, updating");
            palette.colors[transparent_idx] = palette.colors[0];
            palette.colors_rgba[transparent_idx] = palette.colors_rgba[0];
            for b in bytes.iter_mut() {
                *b = maybe_change_nibbles(
                    *b,
                    0,
                    transparent_idx
                        .try_into()
                        .expect("This should never happen, palette is limited to 16 colors"),
                );
            }
        }
    } else {
        // There is no transparent color, avoid using first color at all.
        if let Some(free_idx) = palette.colors.iter().skip(1).position(|p| p.is_none()) {
            // +1 to skip over the first idx.
            let free_idx = free_idx + 1;
            palette.colors[free_idx] = palette.colors[0];
            palette.colors_rgba[free_idx] = palette.colors_rgba[0];
            for b in bytes.iter_mut() {
                *b = maybe_change_nibbles(
                    *b,
                    0,
                    free_idx
                        .try_into()
                        .expect("This should never happen, palette is limited to 16 colors"),
                );
            }
        }
    }

    // Set the BG color.
    palette.colors[0] = Some(BG_COLOR.to_rgb444());
    palette.colors_rgba[0] = Some(BG_COLOR);

    Ok((palette, bytes.to_vec()))
}

/// Extracts 8x8 pixel tiles from a 4-bit-per-pixel image. This essentially just reoderes
/// the bytes (2 pixel per byte):
///
/// (0,0) (1,0) (2,0) (3,0) (4,0) ..
/// (0,1) (1,1) (2,1) (3,1) (4,1) ..
/// ..
///
/// will be converted to
/// (0,0) (1,0) (2,0) (3,0) (0,1) (1,1) ..
pub fn image_to_tiles(
    image: &Vec<u8>,
    width_in_tiles: usize,
    height_in_tiles: usize,
    sprite_switch: Option<TilesetSpriteParameters>,
) -> Vec<u8> {
    debug!(
        "image len: {} width in tiles: {} height in tiles: {}",
        image.len(),
        width_in_tiles,
        height_in_tiles
    );

    // Each tile is 8x8, however stored in 4bpp = 8x4.
    const TILE_HEIGHT: usize = 8;
    const TILE_WIDTH: usize = 4;
    let input_pixel_at = |x: usize, y: usize| -> u8 {
        let pixels_per_row = width_in_tiles * TILE_WIDTH;
        image[y * pixels_per_row + x]
    };

    assert_eq!(
        width_in_tiles * height_in_tiles * TILE_WIDTH * TILE_HEIGHT,
        image.len()
    );

    let mut rv = Vec::new();
    if let Some(sprite_switch) = sprite_switch {
        let sprites_per_row = sprite_switch.sprites_per_row;
        let sprites_per_col = sprite_switch.sprites_per_column;
        if width_in_tiles % sprites_per_row > 0 {
            warn!(
                "Width ({width_in_tiles}) is not a multiple of sprites per row ({sprites_per_row})"
            );
        }
        if height_in_tiles % sprites_per_col > 0 {
            warn!(
                "Height ({height_in_tiles}) is not a multiple of sprites per column ({sprites_per_col})"
            );
        }
        let sprite_width = width_in_tiles / sprites_per_row;
        let sprite_height = height_in_tiles / sprites_per_col;
        for sprite_y in 0..sprites_per_col {
            for sprite_x in 0..sprites_per_row {
                for sub_sprite in &sprite_switch.sub_sprites {
                    for sprite_tile_x in sub_sprite.x / 8..sub_sprite.x / 8 + sub_sprite.width {
                        for sprite_tile_y in sub_sprite.y / 8..sub_sprite.y / 8 + sub_sprite.height
                        {
                            let tile_offset_y =
                                (sprite_y * sprite_height + sprite_tile_y) * TILE_HEIGHT;
                            let tile_offset_x =
                                (sprite_x * sprite_width + sprite_tile_x) * TILE_WIDTH;

                            // Iterate over each pixel of the 8x8 tile
                            for in_tile_y in 0..8 {
                                // Only counting up to 4 since 4 bit per pixel
                                for in_tile_x in 0..4 {
                                    rv.push(input_pixel_at(
                                        tile_offset_x + in_tile_x,
                                        tile_offset_y + in_tile_y,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        for tile_y in 0..height_in_tiles {
            for tile_x in 0..width_in_tiles {
                let tile_offset_y = tile_y * TILE_HEIGHT;
                let tile_offset_x = tile_x * TILE_WIDTH;

                // Iterate over each pixel of the 8x8 tile
                for in_tile_y in 0..8 {
                    // Only counting up to 4 since 4 bit per pixel
                    for in_tile_x in 0..4 {
                        rv.push(input_pixel_at(
                            tile_offset_x + in_tile_x,
                            tile_offset_y + in_tile_y,
                        ));
                    }
                }
            }
        }
    }

    rv
}

#[derive(serde_derive::Serialize)]
pub(crate) struct TilesetSerializationData {
    tiles: Vec<[u8; 8 * 4]>,
    palette: char,
}

pub(crate) struct TilesetSpriteParameters {
    pub(crate) sprites_per_row: usize,
    pub(crate) sprites_per_column: usize,
    // A BigSprite consists of several Mega Drive sprites
    // of varying tile sizes (up to 4x4)
    pub(crate) sub_sprites: Vec<SubSpriteData>,
}

#[derive(serde_derive::Serialize, Clone)]
pub(crate) struct SubSpriteData {
    // Position relative to the main sprite, in tiles
    pub(crate) x: usize,
    pub(crate) y: usize,
    // Dimensions in tiles
    pub(crate) width: usize,
    pub(crate) height: usize,
    // Offset of sub-sprite's tile from the BigSprite base tile
    pub(crate) tile_offset: usize,
}

/// Convert map to rust code. Returns the name of the tileset used.
pub fn convert_tileset(
    tsx_file: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    palette: GamePalette,
    palette_data: &mut Palette,
    sprite_switch: Option<TilesetSpriteParameters>,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut loader = Loader::new();
    let tileset = loader.load_tsx_tileset(tsx_file)?;

    std::fs::create_dir_all(&output_dir)?;

    let image = load_png(
        tileset
            .image
            .as_ref()
            .expect("Tileset has no assigned image")
            .source
            .clone(),
    )?;

    if tileset.tile_width % 8 != 0 || tileset.tile_height % 8 != 0 {
        panic!("Invalid sprite dimensions");
    }
    eprintln!("XX try_apply_existing_palette {:?}", tileset.image);
    let (new_palette, new_image) =
        crate::try_apply_existing_palette(palette_data, &image.0, &image.1)?;
    *palette_data = new_palette;

    let tileset_name = filepath_to_module_name(&tileset.source);

    let mut path = output_dir.as_ref().to_path_buf();
    path.push(format!("{}.rs", tileset_name));

    write_img_data_to_tileset(
        &new_image,
        path,
        tileset.image.as_ref().unwrap().width as usize / 8,
        tileset.image.as_ref().unwrap().height as usize / 8,
        palette,
        sprite_switch,
    )?;
    Ok(tileset_name)
}

/// Convert image data to rust tileset code.
pub fn write_img_data_to_tileset(
    image: &Vec<u8>,
    path: impl AsRef<Path>,
    width_in_tiles: usize,
    height_in_tiles: usize,
    palette: GamePalette,
    sprite_switch: Option<TilesetSpriteParameters>,
) -> Result<(), Box<dyn std::error::Error>> {
    let tiles = image_to_tiles(image, width_in_tiles, height_in_tiles, sprite_switch);

    let mut tiles_data = TilesetSerializationData {
        tiles: Vec::new(),
        palette: palette.into(),
    };

    for idx in 0..tiles.len() / (8 * 4) {
        let mut tile = [0u8; 8 * 4];
        tile.copy_from_slice(&tiles[idx * 8 * 4..(idx + 1) * 8 * 4]);
        tiles_data.tiles.push(tile);
    }

    let source = include_str!("../templates/tiles.rs");
    let handlebars = handlebars::Handlebars::new();
    let rendered = handlebars.render_template(source, &tiles_data).unwrap();

    std::fs::write(path, rendered)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_loading_works() {
        let result = load_png("assets/player.png");
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.0.colors[14].is_none());
        assert!(result.0.colors[0].is_some());
    }

    #[test]
    fn conversion_to_tiles_works() {
        let result = load_png("assets/player.png");
        assert!(result.is_ok());
        let result = result.unwrap();

        let tiles = image_to_tiles(&result.1, 8, 12, None);
        assert_eq!(tiles.len(), 8 * 12 * 8 * 4);
    }
}
