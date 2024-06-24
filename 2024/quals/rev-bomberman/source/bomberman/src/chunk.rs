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
use crate::Grid2dPosition;

use std::collections::HashSet;

use bevy::prelude::*;

pub const CHUNK_SIZE: usize = 16;

#[derive(Component)]
pub struct Loaded;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Component, Reflect)]
pub struct ChunkIndex {
    pub x: i32,
    pub y: i32,
}

impl ChunkIndex {
    pub fn positions(self) -> impl Iterator<Item = Grid2dPosition> {
        let start = Grid2dPosition::from(self);
        (0..(CHUNK_SIZE * CHUNK_SIZE)).map(move |idx| {
            let dx = (idx % CHUNK_SIZE) as i32;
            let dy = (idx / CHUNK_SIZE) as i32;

            Grid2dPosition {
                x: start.x + dx,
                y: start.y + dy,
            }
        })
    }

    pub fn contains(&self, pos: &Grid2dPosition) -> bool {
        pos.x / (CHUNK_SIZE as i32) == self.x && pos.y / (CHUNK_SIZE as i32) == self.y
    }
}

impl From<ChunkIndex> for Grid2dPosition {
    fn from(v: ChunkIndex) -> Grid2dPosition {
        Grid2dPosition {
            x: v.x * CHUNK_SIZE as i32,
            y: v.y * CHUNK_SIZE as i32,
        }
    }
}

impl From<Grid2dPosition> for ChunkIndex {
    fn from(v: Grid2dPosition) -> ChunkIndex {
        ChunkIndex {
            x: v.x / CHUNK_SIZE as i32,
            y: v.y / CHUNK_SIZE as i32,
        }
    }
}

#[derive(Component)]
pub struct LoadedChunk;

#[derive(Event, Debug, Clone, PartialEq, Eq)]
pub enum ChunkEvent {
    LoadChunk(ChunkIndex),
    UnloadChunk(ChunkIndex),
}

// Force all chunks to be unloaded (and loaded again)
#[derive(Event, Debug, Clone, PartialEq, Eq, Default)]
pub struct FlushChunksEvent;

pub fn mark_chunks_to_be_loaded(
    mut commands: Commands,
    camera_q: Query<(&Camera, &GlobalTransform)>,
    currently_loaded: Query<(Entity, &ChunkIndex), With<LoadedChunk>>,
    // Events
    mut ev_chunk: EventWriter<ChunkEvent>,

    mut ev_chunk_flush: EventReader<FlushChunksEvent>,

    map: Res<crate::map::Map>,
) {
    // Calculate set of chunks that should be loaded.
    let Ok((cam, transform)) = camera_q.get_single() else {
        return;
    };
    let Some(viewport_size) = cam.logical_viewport_size() else {
        return;
    };
    let Some(top_left) = cam.viewport_to_world_2d(transform, Vec2::new(0.0, 0.0)) else {
        return;
    };
    let Some(bot_right) = cam.viewport_to_world_2d(transform, viewport_size) else {
        return;
    };

    let mut should_flush = false;
    for _ in &mut ev_chunk_flush {
        should_flush = true;
    }
    let top_left = Grid2dPosition::from(top_left);
    let bot_right = Grid2dPosition::from(bot_right);

    let mut target_chunk_set = HashSet::new();

    const GRACE_TILES: i32 = CHUNK_SIZE as i32;

    let x_max = bot_right.x + GRACE_TILES;
    let x_min = top_left.x - GRACE_TILES;

    let y_min = bot_right.y - GRACE_TILES;
    let y_max = top_left.y + GRACE_TILES;

    if should_flush {
        // Drop all loaded chunks
        for (id, index) in &currently_loaded {
            commands.entity(id).despawn();
            ev_chunk.send(ChunkEvent::UnloadChunk(*index));
        }

        return;
    }

    // TODO: optimize
    for x in x_min.max(0)..x_max.min(map.width) {
        for y in y_min.max(0)..y_max.min(map.height) {
            let p = Grid2dPosition { x, y };
            target_chunk_set.insert(ChunkIndex::from(p));
        }
    }

    let mut to_load = target_chunk_set.clone();

    // Calculate currently loaded chunks and drop the ones no longer needed.
    for (id, index) in &currently_loaded {
        if !target_chunk_set.contains(index) {
            commands.entity(id).despawn();
            ev_chunk.send(ChunkEvent::UnloadChunk(*index));
        } else {
            to_load.remove(index);
        }
    }

    for chunk in &to_load {
        commands.spawn((*chunk, LoadedChunk));
        ev_chunk.send(ChunkEvent::LoadChunk(*chunk));
    }
}
