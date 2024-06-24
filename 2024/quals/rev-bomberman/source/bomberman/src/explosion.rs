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

#[derive(Component)]
pub struct Explosion {
    expires: Timer,
}

impl Default for Explosion {
    fn default() -> Self {
        Self {
            expires: Timer::new(std::time::Duration::from_millis(100), TimerMode::Once),
        }
    }
}

pub fn update(
    mut commands: Commands,
    mut explosions: Query<(Entity, &mut Explosion)>,
    time: Res<Time>,
) {
    for (e, mut expl) in explosions.iter_mut() {
        expl.expires.tick(time.delta());
        if expl.expires.finished() {
            commands.entity(e).despawn();
        }
    }
}
