// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.



use rand::{self, Rng};
use enum_primitive::FromPrimitive;

enum_from_primitive! {
    #[repr(u8)]
    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub enum Color {
        W = 0,
        G = 1,
        R = 2,
        B = 3,
        O = 4,
        Y = 5,
    }
}

impl rand::Rand for Color {
    fn rand<R: Rng>(rng: &mut R) -> Color {
        Color::from_i32(rng.gen_range(0, 6)).unwrap()
    }
}

impl Default for Color {
    fn default() -> Color {
        Color::R
    }
}

impl Color {
    pub fn draw(self) {
        use self::Color::*;
        let s = match self {
            R => 41,
            G => 42,
            Y => 43,
            B => 44,
            O => 45,
            W => 107,
        };
        print!("\x1b[{}m ", s);
    }

    pub fn serialize(&self) -> &'static str {
        use self::Color::*;
        match *self {
            R => "R",
            G => "G",
            Y => "Y",
            B => "B",
            O => "O",
            W => "W",
        }
    }

    pub fn unserialize(c: char) -> Option<Color> {
        use self::Color::*;
        match c {
            'R' => Some(R),
            'G' => Some(G),
            'Y' => Some(Y),
            'B' => Some(B),
            'O' => Some(O),
            'W' => Some(W),
            _ => None,
        }
    }
}
