use megahx8::*;
use crate::res::maps;
use crate::res::maps::WorldType;

// Returns palettes for a given slot in a given world.
pub fn get_palette(p: Palette, t: maps::WorldType) -> [u16; 16] {
    return match p {
{{#each global_palettes}}        Palette::{{@key}} => {{this}},
{{/each}}
{{#each world_palettes}}        Palette::{{@key}} => match t {
{{#each this}}            maps::WorldType::{{@key}} => {{this}},
{{/each}}
        },
{{/each}}
    }
}

// Loads palettes for a given world.
pub fn load_world_palette(t: WorldType, vdp: &mut TargetVdp) {
    for p in [Palette::A, Palette::B, Palette::C, Palette::D] {
        vdp.set_palette(p, &get_palette(p, t));
    }
}
