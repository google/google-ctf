{{#each tilesets}}pub mod {{this}};
{{/each}}

use megahx8::*;

pub const NUM_ENTRIES: usize = {{tilesets_count}};
pub const TILESETS: [&[Tile]; {{tilesets_count}}] = [
{{#each tilesets}}          {{this}}::TILES,
{{/each}}
];
