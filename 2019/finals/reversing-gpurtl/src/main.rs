// Copyright 2019 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod config;
pub mod glsl;
pub mod gpu;
pub mod hacks;
pub mod simulation;
pub mod util;

use clap::{crate_version, App, Arg};

fn main() {
    let matches = App::new("gpurtl")
        .version(crate_version!())
        .author("Robin McCorkell <rmccorkell@google.com>")
        .arg(
            Arg::with_name("prog")
                .help("Programming config")
                .required(true),
        )
        .arg(
            Arg::with_name("script")
                .help("Script to define the simulation")
                .required(true),
        )
        .get_matches();

    let config_data =
        std::fs::read(matches.value_of("prog").unwrap()).expect("reading programming config");
    let config = config::Config::new(&config_data);

    let script = std::fs::read(matches.value_of("script").unwrap()).expect("reading script");

    let sim = simulation::Simulation::init(&config, script);
    sim.execute().expect("running simulation");
}
