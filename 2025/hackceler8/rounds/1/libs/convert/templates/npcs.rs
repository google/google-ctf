use crate::big_sprite::SpriteInitializationFunction;

#[repr(u16)]
#[derive(Copy, Clone, PartialEq)]
pub enum NpcType {
{{#each this}}    {{this.name}},
{{/each}}
}

pub fn sprite_init_fn(npc_type: NpcType) -> SpriteInitializationFunction {
    match npc_type {
{{#each this}}        NpcType::{{this.name}} => crate::res::sprites::{{this.module}}::new,
{{/each}}
    }
}
