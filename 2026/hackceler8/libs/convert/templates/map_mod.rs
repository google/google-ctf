use crate::map_data::MapData;
use crate::res::palettes::PaletteContext;

// Each map root
{{#each map}}pub mod {{this.0}};
{{/each}}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum MapType {
{{#each map}}    {{this.1}},
{{/each}}
}

pub const ALL_MAP_TYPES: &[MapType] = &[
{{#each map}}    MapType::{{this.1}},
{{/each}}
];

pub const MAP_COUNT: usize = ALL_MAP_TYPES.len();

pub fn map_data(map_type: MapType) -> MapData {
    match map_type {
{{#each map}}        MapType::{{this.1}} => {{this.0}}::new(),
{{/each}}
    }
}

pub fn dimensions(map_type: MapType) -> (usize, usize) {
    match map_type {
{{#each map}}        MapType::{{this.1}} => ({{this.0}}::WIDTH, {{this.0}}::HEIGHT),
{{/each}}
    }
}

pub fn palette_type(map_type: MapType) -> PaletteContext {
    match map_type {
{{#each map}}        MapType::{{this.1}} => PaletteContext::{{this.1}},
{{/each}}
    }
}
