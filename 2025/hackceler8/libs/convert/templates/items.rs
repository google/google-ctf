use crate::big_sprite::SpriteInitializationFunction;

#[repr(u16)]
#[derive(Copy, Clone, PartialEq)]
pub enum ItemType {
{{#each this}}    {{this.name}},
{{/each}}
}

pub fn sprite_init_fn(item_type: ItemType) -> SpriteInitializationFunction {
    match item_type {
{{#each this}}        ItemType::{{this.name}} => crate::res::sprites::{{this.module}}::new,
{{/each}}
    }
}
