use megahx8::*;

pub const TILES: &[Tile] = &[
{{#each tiles}}    Tile({{this}}){{#unless @last}},{{/unless}}
{{/each}}
];

pub const PALETTE: Palette = Palette::{{palette}};

