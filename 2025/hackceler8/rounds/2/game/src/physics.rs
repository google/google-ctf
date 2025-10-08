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

use resources::MapTileAttribute;

use crate::entity::*;
use crate::Door;
use crate::HitTiles;
use crate::Map;

/// Moves the entity in the given direction, taking collsisions with the
/// map into account.
///
/// Returns the map tiles the entity is colliding with after the move.
pub fn try_move(entity: &mut dyn Entity, map: &Map, doors: &[Door], dx: i16, dy: i16) -> HitTiles {
    let hitbox = entity.hitbox();
    // If we can go diagonally, do so
    let (hit_solid, hits) = hits_solid(&hitbox.offset(dx, dy), map, doors);
    if !hit_solid {
        entity.move_relative(dx, dy);
        return hits;
    }

    // Attempt to go vertically.
    let (hit_solid, hits) = hits_solid(&hitbox.offset(0, dy), map, doors);
    if !hit_solid {
        entity.move_relative(0, dy);
        return hits;
    }

    // Attempt to go horizontally.
    let (hit_solid, hits) = hits_solid(&hitbox.offset(dx, 0), map, doors);
    if !hit_solid {
        entity.move_relative(dx, 0);
    }
    hits
}

/// Checks if the the given hitbox hits any solid objects
/// (walls on the map or closed doors).
/// Returns the result along with the list of map tiles that were hit.
fn hits_solid(hitbox: &Hitbox, map: &Map, doors: &[Door]) -> (bool, HitTiles) {
    let hits = map.get_hit_tiles(hitbox);
    if hits.touches_tile(MapTileAttribute::Wall) {
        return (true, hits);
    }
    let hit_doors = doors
        .iter()
        .any(|door| !door.open && door.hitbox().collides(hitbox));
    (hit_doors, hits)
}
