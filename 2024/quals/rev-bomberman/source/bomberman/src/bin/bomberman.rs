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
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]

use bevy::prelude::*;

use bomberman::*;

fn win_system(mut ev_win: EventReader<WinEvent>) {
    if ev_win.iter().next().is_some() {
        std::process::exit(0);
    }
}

fn main() {
    println!("Arrowkeys, space to place bombs (first column only)");
    println!("I/O to zoom in and out");
    println!("Goal: Explode the flag");

    let mut app = App::new();
    app.add_plugins(DefaultPlugins)
        .add_systems(Update, bevy::window::close_on_esc)
        .add_event::<WinEvent>()
        .add_systems(Update, win_system)
        // Camera stuff
        .add_systems(Startup, camera::setup)
        .add_systems(Update, camera::update)
        // Chunk stuff
        .add_systems(Update, chunk::mark_chunks_to_be_loaded)
        .add_event::<chunk::ChunkEvent>()
        .add_event::<chunk::FlushChunksEvent>()
        // Map stuff
        // Generate dummy map, (will be replaced in map::setup), #techdebt
        .insert_resource(map::Map::generate(10, 9))
        .add_systems(Startup, (map::setup).after(textures::setup))
        .add_systems(Update, map::handle_events)
        // Player stuff
        .add_systems(Startup, (player::setup).after(textures::setup))
        .add_systems(Update, player::update)
        // Bomb stuff
        .init_resource::<bomb::BombTimer>()
        .add_systems(Update, bomb::handle_events)
        .add_systems(Update, bomb::tick_timer)
        // Textures stuff
        .init_resource::<textures::Textures>()
        .add_systems(Startup, textures::setup)
        // Explosion stuff
        .add_systems(Update, explosion::update);

    if std::env::args().skip(1).next() == Some("--fly".to_string()) {
        println!("Fly-hack enabled :)");
        app.init_resource::<crate::Hack>();
    }

    app.register_type::<Grid2dPosition>()
        .register_type::<chunk::ChunkIndex>()
        .run();
}
