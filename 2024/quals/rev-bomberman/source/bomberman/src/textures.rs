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

use std::collections::HashMap;

use crate::map::GroundTile;

#[derive(Resource, Default)]
pub struct Textures {
    pub ground_tiles: HashMap<GroundTile, Handle<Image>>,

    pub bomb: Handle<Image>,
    pub bomb_ignited: Handle<Image>,

    pub player: Handle<Image>,

    pub explosion: Handle<Image>,
}

pub fn setup(asset_server: Res<AssetServer>, mut textures: ResMut<Textures>) {
    let mapping = [
        (GroundTile::PermanentWall, "wall.png"),
        (GroundTile::DestroyableWall, "wall_destructible.png"),
        (GroundTile::Pillar, "pillar.png"),
        (GroundTile::Floor, "ground.png"),
        (GroundTile::Void, "void.png"),
        (GroundTile::Flag, "flag.png"),
    ];

    for (ty, path) in mapping {
        textures.ground_tiles.insert(ty, asset_server.load(path));
    }

    textures.bomb = asset_server.load("bomb.png");
    textures.bomb_ignited = asset_server.load("bomb_ignited.png");

    textures.explosion = asset_server.load("explosion.png");

    textures.player = asset_server.load("player.png");
}
