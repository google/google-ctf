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

use crate::TILE_W;

// In tiles per second
const PLAYER_SPEED: f32 = 80.0;

#[derive(Component)]
pub struct Player {
    pub position: Vec2,
}

pub fn setup(mut commands: Commands, textures: Res<crate::textures::Textures>) {
    let position = Vec2::new(64.0, 512.0);
    commands.spawn((
        Player { position },
        SpriteBundle {
            texture: textures.player.clone(),
            transform: crate::Grid2dPosition::from(position).transform(crate::Layer::Player),
            ..default()
        },
    ));
}

pub fn update(
    mut commands: Commands,

    keys: Res<Input<KeyCode>>,
    mut player_q: Query<(&mut Player, &mut Transform)>,
    time: Res<Time>,
    map: Res<crate::map::Map>,

    gc: Query<&crate::camera::GameCamera>,

    textures: Res<crate::textures::Textures>,

    hack: Option<Res<crate::Hack>>,
) {
    let mut player = player_q.single_mut();
    let mut direction = Vec2::new(0.0, 0.0);
    if keys.pressed(KeyCode::Right) {
        direction.x += 1.0;
    }
    if keys.pressed(KeyCode::Left) {
        direction.x -= 1.0;
    }
    if keys.pressed(KeyCode::Up) {
        direction.y += 1.0;
    }
    if keys.pressed(KeyCode::Down) {
        direction.y -= 1.0;
    }

    if let Some(direction) = direction.try_normalize() {
        let new_pos = player.0.position
            + direction * PLAYER_SPEED * TILE_W * time.delta_seconds() * gc.single().scale;
        let grid_pos = crate::Grid2dPosition::from(new_pos);

        if map
            .ground_at(grid_pos.x, grid_pos.y)
            .map(|x| x.can_walk_on())
            .unwrap_or(false)
            || hack.is_some()
        {
            player.0.position = new_pos;
            *player.1 = Transform::from_xyz(new_pos.x, new_pos.y, crate::Layer::Player.to_z());
        }
    }

    let grid_pos = crate::Grid2dPosition::from(player.0.position);
    if keys.just_pressed(KeyCode::Space) && grid_pos.x <= 2 {
        crate::bomb::place_bomb(
            &mut commands,
            crate::bomb::Bomb {
                delay: 4,
                ignited: true,
                strength: 2,
            },
            grid_pos,
            &textures,
        );
    }
}
