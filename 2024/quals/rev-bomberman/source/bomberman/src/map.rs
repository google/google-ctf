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
use bevy::prelude::*;

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::chunk::{ChunkEvent, ChunkIndex};
use crate::textures::Textures;
use crate::Grid2dPosition;

#[derive(Component)]
pub struct MapTile;

#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    Debug,
    Hash,
    Component,
    Reflect,
    Default,
    Serialize_repr,
    Deserialize_repr,
)]
#[reflect(Default)]
#[repr(u8)]
pub enum GroundTile {
    #[default]
    PermanentWall,
    DestroyableWall,
    Pillar,
    Floor,
    Void,
    Flag,
}

impl GroundTile {
    pub fn on_explode(self) -> GroundTile {
        match self {
            Self::PermanentWall => Self::PermanentWall,
            Self::DestroyableWall => Self::Floor,
            Self::Pillar => Self::PermanentWall,
            Self::Floor => Self::Floor,
            Self::Void => Self::Void,
            Self::Flag => Self::Flag,
        }
    }

    pub fn stops_explosion(self) -> bool {
        match self {
            Self::PermanentWall => true,
            Self::DestroyableWall => true,
            Self::Pillar => false,
            Self::Floor => false,
            Self::Void => false,
            Self::Flag => true,
        }
    }

    pub fn can_walk_on(self) -> bool {
        match self {
            Self::PermanentWall => false,
            Self::DestroyableWall => false,
            Self::Pillar => true,
            Self::Floor => true,
            Self::Void => false,
            Self::Flag => true,
        }
    }
}

#[derive(Resource, Serialize, Deserialize, Reflect, Clone)]
pub struct Map {
    pub width: i32,
    pub height: i32,
    pub ground: Vec<GroundTile>,
}

impl Map {
    fn index(&self, x: i32, y: i32) -> Option<usize> {
        if x < 0 || x >= self.width || y < 0 || y >= self.height {
            None
        } else {
            Some(x as usize + y as usize * self.width as usize)
        }
    }

    pub fn ground_at(&self, x: i32, y: i32) -> Option<GroundTile> {
        self.index(x, y).map(|p| self.ground[p])
    }

    pub fn set_ground_at(&mut self, x: i32, y: i32, tile: GroundTile) -> Option<()> {
        self.index(x, y).map(|p| self.ground[p] = tile)
    }

    pub fn generate(w: i32, h: i32) -> Map {
        assert!(w > 0 && h > 0);

        let ground = vec![GroundTile::Floor; w as usize * h as usize];
        Map {
            width: w,
            height: h,
            ground,
        }
    }
}

fn load_map_tile(commands: &mut Commands, x: i32, y: i32, map: &Map, textures: &Res<Textures>) {
    // Verify index in bounds
    if map.index(x, y).is_none() {
        return;
    }

    let id = commands
        .spawn((
            MapTile,
            SpriteBundle {
                texture: textures
                    .ground_tiles
                    .get(&map.ground_at(x, y).unwrap())
                    .unwrap()
                    .clone(),
                transform: Grid2dPosition { x, y }.transform(crate::Layer::Background),
                ..default()
            },
            Grid2dPosition { x, y },
        ))
        .id();
    if let Some(gnd) = map.ground_at(x, y) {
        commands.entity(id).insert(gnd);
    }
}

pub fn setup(
    commands: Commands,
    map: ResMut<Map>,
    bombs: Query<(Entity, &mut crate::bomb::Bomb, &Grid2dPosition)>,
    ev_chunk_flush: EventWriter<crate::chunk::FlushChunksEvent>,
    textures: Res<crate::textures::Textures>,
) {
    crate::save::load_cbor(
        commands,
        include_bytes!("../generated.cbor"),
        map,
        bombs,
        ev_chunk_flush,
        textures,
    );
}

fn load_chunk(commands: &mut Commands, map: &Map, c: ChunkIndex, textures: &Res<Textures>) {
    for p in c.positions() {
        load_map_tile(commands, p.x, p.y, map, textures);
    }
}

fn unload_chunk(
    commands: &mut Commands,
    loaded_tiles_query: &Query<(Entity, &Grid2dPosition), With<MapTile>>,

    c: ChunkIndex,
) {
    for (id, pos) in loaded_tiles_query {
        if c.contains(pos) {
            commands.entity(id).despawn();
        }
    }
}

pub fn handle_events(
    mut commands: Commands,
    map: Res<Map>,
    loaded_tiles_query: Query<(Entity, &Grid2dPosition), With<MapTile>>,
    textures: Res<Textures>,
    mut ev_chunk: EventReader<ChunkEvent>,
) {
    for event in &mut ev_chunk {
        match event {
            ChunkEvent::LoadChunk(c) => {
                load_chunk(&mut commands, &map, *c, &textures);
            }
            ChunkEvent::UnloadChunk(c) => {
                unload_chunk(&mut commands, &loaded_tiles_query, *c);
            }
        }
    }
}
