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

// Various walking commands: Go in specific directions or pause.
pub enum Cmd {
    Pause = 0,
    Up = 1,
    Down = 2,
    Left = 3,
    Right = 4,
}

// A walk command for an entity: Which direction to go in and for how long.
pub struct WalkData {
    pub cmd: Cmd,
    pub dur: u16,
}

// The current walk state of an entity who may be in the middle of a walk.
pub struct WalkState {
    pub data: &'static [WalkData],
    pos: usize,
    timer: u16,
}

impl WalkState {
    pub fn new(walk_data: &'static [WalkData]) -> WalkState {
        let timer = if walk_data.is_empty() {
            0
        } else {
            walk_data[0].dur
        };
        Self {
            data: walk_data,
            pos: 0,
            timer,
        }
    }

    // Proceeds to the next phase of walking and returns the direction the player should walk in.
    pub fn update(&mut self) -> (i16, i16) {
        if self.data.is_empty() {
            return (0, 0);
        }

        if self.timer == 0 {
            self.pos += 1;
            if self.pos == self.data.len() {
                self.pos = 0;
            }
            self.timer = self.data[self.pos].dur;
        } else {
            self.timer -= 1;
        }
        match &self.data[self.pos].cmd {
            Cmd::Pause => (0, 0),
            Cmd::Up => (0, -100),
            Cmd::Down => (0, 100),
            Cmd::Left => (-100, 0),
            Cmd::Right => (100, 0),
        }
    }
}
