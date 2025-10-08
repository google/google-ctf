// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an AS IS BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_std]

use bitmask_enum::bitmask;

// Shared definitions for resource generation + loading.

/// Possible attribute values for map tiles.
#[bitmask(u8)]
#[non_exhaustive]
pub enum MapTileAttribute {
    /// No special attribute
    None = 0,
    /// Specific tile is a wall
    Wall,
    /// Specific tile is an entrance
    Entrance,
    /// Specific tile is a spike (= hurts player + enemies on contact)
    Spike,
    /// Specific tile is a hole (= kills player + enemies on contact)
    Hole,
}

impl core::convert::TryFrom<&str> for MapTileAttribute {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "walls" => Ok(MapTileAttribute::Wall),
            "entrances" => Ok(MapTileAttribute::Entrance),
            "spikes" => Ok(MapTileAttribute::Spike),
            "holes" => Ok(MapTileAttribute::Hole),
            _ => Err(()),
        }
    }
}
