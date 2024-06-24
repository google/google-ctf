// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use crate::chunk::ChunkEvent;
use crate::chunk::ChunkIndex;
use crate::chunk::Loaded;
use crate::map::GroundTile;
use crate::map::Map;
use crate::textures::Textures;
use crate::Grid2dPosition;
use crate::WinEvent;
use bevy::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Component, Serialize, Deserialize)]
pub struct Bomb {
    pub strength: i32,
    pub delay: usize,
    pub ignited: bool,
}

pub fn tick_bombs(
    mut commands: Commands,
    mut bombs: Query<(Entity, &mut Bomb, &Grid2dPosition)>,
    mut image: Query<&mut Handle<Image>>,

    mut map: ResMut<Map>,
    map_tiles: Query<(Entity, &Grid2dPosition), Without<Bomb>>,

    textures: &Res<Textures>,
    mut ev_win: EventWriter<WinEvent>,
) {
    let mut ignited_tiles = std::collections::HashSet::new();

    for (entity_id, mut bomb, bomb_pos) in bombs.iter_mut() {
        if bomb.ignited {
            if bomb.delay > 0 {
                bomb.delay -= 1;
            }
            if bomb.delay == 0 {
                commands.entity(entity_id).despawn();

                // Our explosion can be stopped by walls.
                let mut xp_stopped = false;
                let mut xn_stopped = false;
                let mut yp_stopped = false;
                let mut yn_stopped = false;
                for i in 0..=bomb.strength {
                    if !xp_stopped {
                        let x = bomb_pos.x + i;
                        let y = bomb_pos.y;
                        ignited_tiles.insert(Grid2dPosition { x, y });
                        xp_stopped = map
                            .ground_at(x, y)
                            .map(|t| t.stops_explosion())
                            .unwrap_or(false);
                    }

                    if !xn_stopped {
                        let x = bomb_pos.x - i;
                        let y = bomb_pos.y;
                        ignited_tiles.insert(Grid2dPosition { x, y });
                        xn_stopped = map
                            .ground_at(x, y)
                            .map(|t| t.stops_explosion())
                            .unwrap_or(false);
                    }

                    if !yp_stopped {
                        let x = bomb_pos.x;
                        let y = bomb_pos.y + i;
                        ignited_tiles.insert(Grid2dPosition { x, y });
                        yp_stopped = map
                            .ground_at(x, y)
                            .map(|t| t.stops_explosion())
                            .unwrap_or(false);
                    }

                    if !yn_stopped {
                        let x = bomb_pos.x;
                        let y = bomb_pos.y - i;
                        ignited_tiles.insert(Grid2dPosition { x, y });
                        yn_stopped = map
                            .ground_at(x, y)
                            .map(|t| t.stops_explosion())
                            .unwrap_or(false);
                    }
                }
            }
        }
    }

    if ignited_tiles.is_empty() {
        return;
    }

    // Spawn explosion effects for each tile.
    for position in &ignited_tiles {
        commands.spawn((
            crate::explosion::Explosion::default(),
            *position,
            SpriteBundle {
                texture: textures.explosion.clone(),
                transform: position.transform(crate::Layer::Explosion),
                ..default()
            },
        ));
    }

    // Ignite bombs that were in range of the explosion of triggered bombs.
    for (entity, mut bomb, bomb_pos) in bombs.iter_mut() {
        if !bomb.ignited && ignited_tiles.contains(bomb_pos) {
            bomb.ignited = true;
            if let Ok(mut handle) = image.get_mut(entity) {
                *handle = textures.bomb_ignited.clone();
            }
        }
    }

    let mut hmap = std::collections::HashMap::new();
    for (eid, pos) in &map_tiles {
        hmap.insert(pos, eid);
    }

    for position in &ignited_tiles {
        let Some(old) = map.ground_at(position.x, position.y) else {
            continue;
        };
        map.set_ground_at(position.x, position.y, old.on_explode());

        if let Some(&entity) = hmap.get(position) {
            if let Ok(mut handle) = image.get_mut(entity) {
                *handle = textures
                    .ground_tiles
                    .get(&old.on_explode())
                    .cloned()
                    .unwrap();
            }
        }
        if matches!(old, GroundTile::Flag) {
            ev_win.send(Default::default());
            println!("You win :)");
        }
    }
}

fn load_bomb(
    commands: &mut Commands,
    entity: Entity,
    position: Grid2dPosition,
    textures: &Res<Textures>,
) {
    commands.entity(entity).insert((
        SpriteBundle {
            texture: textures.bomb.clone(),
            transform: position.transform(crate::Layer::Bomb),
            ..default()
        },
        Loaded,
    ));
}

pub fn place_bomb(
    commands: &mut Commands,
    bomb: Bomb,
    position: Grid2dPosition,
    textures: &Res<Textures>,
) {
    let id = commands.spawn((bomb, position)).id();
    load_bomb(commands, id, position, textures);
}

pub fn ignite_bomb(
    _commands: &mut Commands,
    position: Grid2dPosition,
    mut bombs: Query<(Entity, &mut Bomb, &Grid2dPosition), With<Bomb>>,
    mut image: Query<&mut Handle<Image>, With<Bomb>>,
    textures: &Res<Textures>,
) -> Option<()> {
    for (entity, mut bomb, &pos) in bombs.iter_mut() {
        if pos == position {
            bomb.ignited = true;
            if let Ok(mut handle) = image.get_mut(entity) {
                *handle = textures.bomb_ignited.clone();
            }
            return Some(());
        }
    }

    None
}

fn load_chunk(
    commands: &mut Commands,
    bombs_q: &Query<(Entity, &Grid2dPosition), (With<Bomb>, Without<Loaded>)>,
    c: ChunkIndex,
    textures: &Res<Textures>,
) {
    let mut position_to_bomb = HashMap::new();
    for (e, position) in bombs_q {
        position_to_bomb.insert(position, e);
    }
    for p in c.positions() {
        if let Some(e) = position_to_bomb.get(&p) {
            load_bomb(commands, *e, p, textures);
        }
    }
}

fn unload_chunk(
    commands: &mut Commands,
    loaded_bombs_q: &Query<(Entity, &Grid2dPosition), (With<Bomb>, With<Loaded>)>,
    c: ChunkIndex,
) {
    let unload_positions = c.positions().collect::<HashSet<Grid2dPosition>>();
    for (id, pos) in loaded_bombs_q {
        if unload_positions.contains(pos) {
            commands.entity(id).remove::<Loaded>();
            commands.entity(id).remove::<SpriteBundle>();
        }
    }
}

pub fn handle_events(
    mut commands: Commands,
    unloaded_bombs_q: Query<(Entity, &Grid2dPosition), (With<Bomb>, Without<Loaded>)>,
    loaded_bombs_q: Query<(Entity, &Grid2dPosition), (With<Bomb>, With<Loaded>)>,
    mut ev_chunk: EventReader<ChunkEvent>,
    textures: Res<Textures>,
) {
    for event in &mut ev_chunk {
        match event {
            ChunkEvent::LoadChunk(c) => {
                load_chunk(&mut commands, &unloaded_bombs_q, *c, &textures);
            }
            ChunkEvent::UnloadChunk(c) => {
                unload_chunk(&mut commands, &loaded_bombs_q, *c);
            }
        }
    }
}

#[derive(Resource)]
pub struct BombTimer(Timer);

impl Default for BombTimer {
    fn default() -> Self {
        Self(Timer::new(
            std::time::Duration::from_micros(100),
            TimerMode::Repeating,
        ))
    }
}

pub fn tick_timer(
    mut bomb_timer: ResMut<BombTimer>,
    time: Res<Time>,

    commands: Commands,
    bombs: Query<(Entity, &mut Bomb, &Grid2dPosition)>,
    image: Query<&mut Handle<Image>>,
    map: ResMut<Map>,
    map_tiles: Query<(Entity, &Grid2dPosition), Without<Bomb>>,

    textures: Res<crate::textures::Textures>,
    ev_win: EventWriter<WinEvent>,
) {
    bomb_timer.0.tick(time.delta());
    if bomb_timer.0.finished() {
        tick_bombs(commands, bombs, image, map, map_tiles, &textures, ev_win);
    }
}
