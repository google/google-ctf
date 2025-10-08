use crate::map::NewFn;

{{#each map_identifiers}}{{#if this}}pub mod {{this.0}};
{{/if}}{{/each}}

// pub const IDENTIFIER: &str = "{{identifier}}";

// Width of the world in maps
pub const WIDTH: usize = {{width}};
// Height of the world in maps
pub const HEIGHT: usize = {{height}};

pub const MAPS: [Option<NewFn>; {{width}}*{{height}}] = [
{{#each map_identifiers}}    {{#if this}}Some({{this.0}}::new){{else}}None{{/if}}{{#unless @last}},{{/unless}}
{{/each}}
];

pub const START_COORDS: (i16, i16) = {{#if spawn_pos}}({{spawn_pos.0}},{{spawn_pos.1}});{{else}}(0, 0); // UNSET{{/if}}

pub fn map(x: i16, y: i16) -> Option<NewFn> {
    if x < 0 || y < 0 {
        panic!("Map coordinate underflow");
    }

    let x = x as usize;
    let y = y as usize;

    if x >= WIDTH || y >= HEIGHT {
        panic!("Map coordinate overflow");
    }

    let idx = y * WIDTH + x;

    MAPS[idx]
}

pub fn map_module_name(x: i16, y: i16) -> Option<&'static str> {
    match (x, y) {
{{#each map_identifiers}}
    {{#if this}}
        ({{this.1}}, {{this.2}}) => Some("{{this.0}}"),
    {{/if}}
{{/each}}
        _ => None,
    }
}
