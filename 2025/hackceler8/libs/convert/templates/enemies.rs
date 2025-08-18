use crate::big_sprite::SpriteInitializationFunction;

#[repr(u16)]
#[derive(Copy, Clone, PartialEq)]
pub enum EnemyType {
{{#each enemies}}    {{this.name}} = {{this.value}},
{{/each}}
}

pub fn sprite_init_fn(enemy_type: EnemyType) -> SpriteInitializationFunction {
    match enemy_type {
{{#each enemies}}        EnemyType::{{this.name}} => crate::res::sprites::{{this.module}}::new,
{{/each}}
    }
}
