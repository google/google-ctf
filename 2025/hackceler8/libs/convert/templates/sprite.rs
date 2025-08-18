use megahx8::*;
use crate::big_sprite::*;
use crate::resource_state::State;
use crate::res::tileset::{{tileset}}::PALETTE;

const SPRITES: &[Sprite] = &[
{{#each sprites as |definition definition_idx|}}
    Sprite {
        size: SpriteSize::Size{{this.width}}x{{this.height}},
        x: {{this.x}},
        y: {{this.y}},
        link: 0,
        flags: TileFlags::for_tile({{this.tile_offset}}, PALETTE)
    },
{{/each}}
];

{{#if animation_definitions}}
#[derive(Copy, Clone)]
#[repr(u8)]
#[allow(dead_code)]
pub enum Anim {
{{#each animation_definitions as |definition definition_idx|}}    {{definition.name}}{{#unless @last}},{{/unless}}
{{/each}}
}
{{/if}}
const ANIMS: &[Animation] = &[
{{#each animation_definitions as |definition definition_idx|}}
    Animation { loops: {{definition.loops}}, frames: &[
{{#each definition.frames}}        Frame { tile_offs: {{this.tile_offset}}, duration: {{this.duration}} }{{#unless @last}},{{/unless}}
{{/each}}
    ]}{{#unless @last}},{{/unless}}
{{/each}}
];

pub fn new(state: &mut State, vdp: &mut TargetVdp, keep_loaded: bool) ->  BigSprite {
    BigSprite::new(state, vdp, /*tiles_idx=*/{{tiles_idx}}, /*w=*/{{width}}, /*h=*/{{height}}, SPRITES, ANIMS, keep_loaded)
}
