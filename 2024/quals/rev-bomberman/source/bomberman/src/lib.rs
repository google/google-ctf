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
pub mod bomb;
pub mod camera;
pub mod chunk;
pub mod explosion;
pub mod map;
pub mod player;
pub mod prelude;
pub mod save;
pub mod textures;

pub use prelude::*;

use bevy::prelude::*;

#[derive(Event, Default)]
pub struct WinEvent;

#[derive(Default, Resource)]
pub struct Hack;
