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

use crate::filepath_to_module_name;
use crate::tileset;
use crate::PaletteID;

#[derive(serde_derive::Serialize)]
pub(crate) struct ImageSerializationData {
    name: String,
    tiles_idx: usize,
    width: u16,
    height: u16,
}

pub fn convert_image(
    png_file: impl AsRef<Path>,
    images_dir: impl AsRef<Path>,
    tileset_dir: impl AsRef<Path>,
    tileset_id: usize,
    palette_id: &PaletteID,
    palette_data: &mut crate::Palette,
) -> Result<(), Box<dyn std::error::Error>> {
    let png_file = png_file.as_ref();
    let img_name = filepath_to_module_name(&png_file.file_stem().unwrap().to_str().unwrap());

    info!("Converting static image from {png_file:?}");

    let decoder = png::Decoder::new(File::open(&png_file)?);
    let reader = decoder.read_info()?;
    let info = reader.info();
    if info.width % 8 != 0 || info.height % 8 != 0 {
        panic!("Invalid image dimensions");
    }

    let image = tileset::load_png(png_file)?;
    let (new_palette, new_image) =
        crate::try_apply_existing_palette(palette_data, &image.0, &image.1)?;
    *palette_data = new_palette;
    let mut tileset_path = tileset_dir.as_ref().to_path_buf();
    tileset_path.push(format!("{}.rs", img_name));

    tileset::write_img_data_to_tileset(
        &new_image,
        tileset_path,
        (info.width / 8) as usize,
        (info.height / 8) as usize,
        palette_id.id.clone(),
        None,
    )?;

    let mut image_path = images_dir.as_ref().to_path_buf();
    image_path.push(format!("{}.rs", img_name));
    let source = include_str!("../templates/image.rs");
    let handlebars = handlebars::Handlebars::new();
    let image_data = ImageSerializationData {
        name: img_name,
        tiles_idx: tileset_id,
        width: (info.width / 8) as u16,
        height: (info.height / 8) as u16,
    };
    let rendered = handlebars.render_template(source, &image_data).unwrap();
    std::fs::write(image_path, rendered)?;

    Ok(())
}
