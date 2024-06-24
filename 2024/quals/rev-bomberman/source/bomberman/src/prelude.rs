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

pub const TILE_W: f32 = 64.0f32;
pub const TILE_H: f32 = 64.0f32;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Layer {
    Background,
    Bomb,
    Player,
    Explosion,
}

impl Layer {
    pub fn to_z(self) -> f32 {
        match self {
            Layer::Background => 0.0,
            Layer::Bomb => 1.0,
            Layer::Player => 2.0,
            Layer::Explosion => 3.0,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Component, Hash, Reflect, Serialize, Deserialize)]
pub struct Grid2dPosition {
    pub x: i32,
    pub y: i32,
}

impl From<Vec2> for Grid2dPosition {
    fn from(p: Vec2) -> Grid2dPosition {
        Grid2dPosition {
            x: (p.x / TILE_W).round() as i32,
            y: (p.y / TILE_H).round() as i32,
        }
    }
}

impl From<Grid2dPosition> for Transform {
    fn from(p: Grid2dPosition) -> Transform {
        Transform::from_xyz(p.x as f32 * TILE_W, p.y as f32 * TILE_H, 0.0)
    }
}

impl Grid2dPosition {
    pub fn transform(self, layer: Layer) -> Transform {
        Transform::from_xyz(self.x as f32 * TILE_W, self.y as f32 * TILE_H, layer.to_z())
    }
}

impl std::ops::Add<Grid2dPosition> for Grid2dPosition {
    type Output = Self;

    fn add(self, rhs: Grid2dPosition) -> Self::Output {
        Self {
            x: self.x + rhs.x,
            y: self.y + rhs.y,
        }
    }
}
