#![allow(unused_imports)]
use megahx8::*;
use crate::*;
use crate::map;
use crate::res::tileset::{{tileset_name}}::PALETTE;
use crate::resource_state::State;
use crate::res::enemies::EnemyType;
use crate::res::npcs::NpcType;
use crate::res::items::ItemType;
use crate::door::Orientation;
use crate::door::DoorProperties;
use crate::switch::SwitchProperties;
use crate::enemy::EnemyProperties;
use crate::npc::NpcProperties;
use crate::item::ItemProperties;
use crate::walk::*;

const GFX_LAYER: &[u16] = &[{{#each gfx_layer}}{{this}}{{#unless @last}},{{/unless}}{{/each}}];

const ATTR_LAYER: &[u8] = &[{{#each attr_layer}}{{this}}{{#unless @last}},{{/unless}}{{/each}}];

pub const PLAYER_SPAWN_POSITION: Option<(i16, i16)> ={{#if player_spawn_position}}Some(({{player_spawn_position.[0]}}, {{player_spawn_position.[1]}})){{^}}None{{/if}};

const ENEMIES: &[(EnemyType, u16, i16, i16, &EnemyProperties)] = &[{{#each enemies}}
    (EnemyType::{{this.kind}}, {{this.id}}, {{this.x}}, {{this.y}}, &EnemyProperties{
        speed: {{#if this.properties.speed}}Some({{this.properties.speed}}){{^}}None{{/if}},
        health: {{#if this.properties.health}}Some({{this.properties.health}}){{^}}None{{/if}},
        strength: {{#if this.properties.strength}}Some({{this.properties.strength}}){{^}}None{{/if}},
        invulnerable:  {{this.properties.invulnerable}},
        flags:  {{#if this.properties.flags}}Some({{this.properties.flags}}){{^}}None{{/if}},
        walk_data: &[{{#each this.properties.walk_data as |walkies walkies_idx|}}
                WalkData { cmd: Cmd::{{walkies.command}}, dur: {{walkies.duration}} },{{/each}}
        ],
    }),{{/each}}
];

const NPCS: &[(NpcType, i16, i16, &NpcProperties)] = &[{{#each npcs}}
    (NpcType::{{this.kind}}, {{this.x}}, {{this.y}}, &NpcProperties{dialogue_id: {{this.dialogue_id}}}),{{/each}}
];

const ITEMS: &[(ItemType, i16, i16, &ItemProperties)] = &[{{#each items}}
    (ItemType::{{this.kind}}, {{this.x}}, {{this.y}}, &ItemProperties{id: {{this.id}}}),{{/each}}
];

const DOORS: &[(i16, i16, &DoorProperties)] = &[{{#each doors}}
    ({{this.x}}, {{this.y}}, &DoorProperties{id: {{this.id}}, orientation: Orientation::{{this.orientation}}}),{{/each}}
];

const SWITCHES: &[(i16, i16, &SwitchProperties)] = &[{{#each switches}}
    ({{this.x}}, {{this.y}}, &SwitchProperties{id: {{this.id}}, event_id: {{this.event_id}}}),{{/each}}
];

pub fn new(state: &mut State, vdp: &mut TargetVdp) -> Map {
    Map::new(state, vdp, /*tiles_idx=*/{{tiles_idx}}, map::Array2d::new(GFX_LAYER, map::WIDTH, map::HEIGHT), map::Array2d::new(ATTR_LAYER, map::WIDTH, map::HEIGHT), PALETTE, PLAYER_SPAWN_POSITION, ENEMIES, NPCS, ITEMS, DOORS, SWITCHES)
}
