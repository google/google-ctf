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

use megahx8::*;

use crate::big_sprite::BigSprite;
use crate::player::Status;
use crate::player::ID;
use crate::res::enemies::EnemyType;
use crate::res::sprites::hat_base as HatSprite;
use crate::resource_state::State;
use crate::Direction;

/// "Random" offsets of the 2 explosion sprites that appear during the boss defeat sequence.
pub const EXPLOSION_OFFSETS: [[(i16, i16); 8]; 2] = [
    [
        (-47, -37),
        (33, 27),
        (54, -20),
        (35, -34),
        (47, -14),
        (32, 14),
        (-1, -6),
        (25, -25),
    ],
    [
        (-39, -13),
        (-38, -13),
        (-36, 22),
        (-19, -32),
        (4, 13),
        (-53, -38),
        (38, 9),
        (-53, 15),
    ],
];

/// Returns the offset of the crown sprite for a miniboss of the given type facing a given direction
pub fn crown_offset(enemy_type: EnemyType, facing: Direction) -> (i16, i16) {
    match enemy_type {
        EnemyType::Angel => match facing {
            Direction::Left => (-1, -25),
            _ => (1, -25),
        },
        EnemyType::Octopus => match facing {
            Direction::Left => (-1, -22),
            _ => (1, -22),
        },
        EnemyType::Goblin | EnemyType::Orc => match facing {
            Direction::Left | Direction::Up => (-1, -31),
            Direction::Right | Direction::Down => (1, -31),
        },
        EnemyType::Siren => match facing {
            Direction::Left | Direction::Up => (-2, -30),
            Direction::Right | Direction::Down => (2, -30),
        },
        EnemyType::Blob => (0, -23),
        EnemyType::Flameboi => (0, -18),
        EnemyType::Archer => match facing {
            Direction::Left => (3, -31),
            Direction::Right => (-3, -31),
            Direction::Up => (0, -32),
            Direction::Down => (0, -32),
        },
        _ => {
            panic!("Enemy can't be a miniboss")
        }
    }
}

/// Return the offset of the hat sprite relative to a player based
/// on the player status and direction.
pub fn get_player_hat_position(status: Status, facing: Direction) -> (i16, i16) {
    match status {
        Status::Attacking { .. } => match facing {
            Direction::Right => (-7, -25),
            Direction::Left => (-7, -25),
            Direction::Up => (-7, -26),
            _ => (-8, -24),
        },
        _ => match facing {
            Direction::Left => (-6, -25),
            Direction::Up => (-7, -25),
            _ => (-8, -25),
        },
    }
}

/// Return the animation of a hat sprite based on the player's properties.
pub fn get_player_hat_anim(status: Status, id: ID) -> HatSprite::Anim {
    match status {
        Status::KnockedBack { .. } => match id {
            ID::P1 => HatSprite::Anim::Damage1,
            ID::P2 => HatSprite::Anim::Damage2,
            ID::P3 => HatSprite::Anim::Damage3,
            ID::P4 => HatSprite::Anim::Damage4,
        },
        _ => match id {
            ID::P1 => HatSprite::Anim::Idle1,
            ID::P2 => HatSprite::Anim::Idle2,
            ID::P3 => HatSprite::Anim::Idle3,
            ID::P4 => HatSprite::Anim::Idle4,
        },
    }
}

/// Return the team-specific player sprite based on the team ID.
pub fn get_player_sprite(team_id: u8, res_state: &mut State, vdp: &mut TargetVdp) -> BigSprite {
    [
        crate::res::sprites::player_base::new,
        crate::res::sprites::player_team1::new,
        crate::res::sprites::player_team2::new,
        crate::res::sprites::player_team3::new,
        crate::res::sprites::player_team4::new,
        crate::res::sprites::player_team5::new,
        crate::res::sprites::player_team6::new,
        crate::res::sprites::player_team7::new,
        crate::res::sprites::player_team8::new,
    ][team_id as usize](res_state, vdp, /* keep_loaded= */ true)
}

/// Return the team-specific player hat sprite based on the team ID.
pub fn get_hat_sprite(team_id: u8, res_state: &mut State, vdp: &mut TargetVdp) -> BigSprite {
    [
        crate::res::sprites::hat_base::new,
        crate::res::sprites::hat_team1::new,
        crate::res::sprites::hat_team2::new,
        crate::res::sprites::hat_team3::new,
        crate::res::sprites::hat_team4::new,
        crate::res::sprites::hat_team5::new,
        crate::res::sprites::hat_team6::new,
        crate::res::sprites::hat_team7::new,
        crate::res::sprites::hat_team8::new,
    ][team_id as usize](res_state, vdp, /* keep_loaded= */ true)
}
