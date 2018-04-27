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



use color::Color;
use permutation::Permutation;
use std::{fmt, hash};
use rand;

#[derive(Copy)]
pub struct Cube {
    pub colors: [Color; 54],
}

impl Clone for Cube {
    fn clone(&self) -> Cube {
        *self
    }
}

impl fmt::Debug for Cube {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Cube {{ perm: {:?} }}", &self.colors[..])
    }
}

impl PartialEq for Cube {
    fn eq(&self, other: &Cube) -> bool {
        &self.colors[..] == &other.colors[..]
    }
}
impl Eq for Cube {}

impl hash::Hash for Cube {
    fn hash<H>(&self, state: &mut H)
        where H: hash::Hasher
    {
        self.colors.hash(state)
    }
}

impl Default for Cube {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn default() -> Cube {
        use self::Color::*;
        Cube {
            colors: [         W, W, W,
                              W, W, W,
                              W, W, W,
                     G, G, G, R, R, R, B, B, B, O, O, O,
                     G, G, G, R, R, R, B, B, B, O, O, O,
                     G, G, G, R, R, R, B, B, B, O, O, O,
                              Y, Y, Y,
                              Y, Y, Y,
                              Y, Y, Y]
        }
    }
}

impl rand::Rand for Cube {
    fn rand<R: rand::Rng>(rng: &mut R) -> Cube {
        let mut colors = [Default::default(); 54];
        for pos in 0..54 {
            colors[pos] = rng.gen();
        }
        Cube { colors: colors }
    }
}

impl Cube {
    pub fn draw(&self) {
        let mut ndx = 0;

        // Draw top
        for _row in 0..3 {
            print!("   ");
            for _col in 0..3 {
                self.colors[ndx].draw();
                ndx += 1;
            }
            println!("\x1b[0m");
        }

        // Draw middle
        for _row in 0..3 {
            for _col in 0..12 {
                self.colors[ndx].draw();
                ndx += 1;
            }
            println!("\x1b[0m");
        }

        // Draw top
        for _row in 0..3 {
            print!("   ");
            for _col in 0..3 {
                self.colors[ndx].draw();
                ndx += 1;
            }
            println!("\x1b[0m");
        }
        println!();
    }

    pub fn apply(&self, perm: Permutation) -> Cube {
        Cube { colors: perm.applyto(&self.colors) }
    }

    pub fn serialize(&self) -> String {
        let mut out = String::with_capacity(9 * 6);
        for c in self.colors.iter() {
            out.push_str(c.serialize());
        }
        out
    }

    pub fn unserialize(s: &str) -> Option<Cube> {
        let mut colors = [Color::R; 54];
        for (n, c) in s.chars().enumerate() {
            if let Some(c) = Color::unserialize(c) {
                colors[n] = c;
                if n == 53 {
                    return Some(Cube { colors: colors });
                }
            } else {
                return None;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{self, Rng};

    #[test]
    fn test_serialize() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let c: Cube = rng.gen();
            assert_eq!(Some(c), Cube::unserialize(&c.serialize()));
        }
    }
}
