use megahx8::*;

#[derive(Copy, Clone)]
pub enum PaletteContext {
{{#each contexts}}    {{this}},
{{/each}}
}

// Returns palettes for a given slot in a given map.
pub fn get_palette(p: Palette, t: PaletteContext) -> [u16; 16] {
    return match p {
{{#each palettes}}        Palette::{{@key}} => match t {
{{#each this.context_specific}}            PaletteContext::{{@key}} => {{this}},
{{/each}}
        _ => {{this.default}},
        },
{{/each}}
    }
}

// Loads palettes for a given local context (e.g. loaded map).
pub fn load_local_palette(t: PaletteContext, vdp: &mut TargetVdp) {
    for p in [Palette::A, Palette::B, Palette::C, Palette::D] {
        vdp.set_palette(p, &get_palette(p, t));
    }
}
