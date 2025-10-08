use crate::map::NewFn;

// Each world root
{{#each world}}pub mod {{this.0}};
{{/each}}

#[derive(Copy, Clone, PartialEq)]
pub enum WorldType {
{{#each world}}    {{this.1}},
{{/each}}
}

// Start coords
pub fn start_coords(world_type: WorldType) -> (i16, i16) {
    match world_type {
{{#each world}}        WorldType::{{this.1}} => {{this.0}}::START_COORDS,
{{/each}}
    }
}

pub fn map(world_type: WorldType, x: i16, y: i16) -> Option<NewFn> {
    match world_type {
{{#each world}}        WorldType::{{this.1}} => {{this.0}}::map(x, y),
{{/each}}
    }
}

pub fn dimensions(world_type: WorldType) -> (usize, usize) {
    match world_type {
{{#each world}}        WorldType::{{this.1}} => ({{this.0}}::WIDTH, {{this.0}}::HEIGHT),
{{/each}}
    }
}
