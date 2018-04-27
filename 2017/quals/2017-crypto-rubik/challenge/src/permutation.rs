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



use std::ops::{Add, Neg, Sub, Mul};
use cube::Cube;
use std::{fmt, hash};
use std::collections::HashMap;
use rand::{self, Rng};

#[derive(Copy)]
pub struct Permutation {
    perm: [u8; 54],
}

struct SeenSet {
    seen: [bool; 54],
}

impl SeenSet {
    fn new() -> SeenSet {
        SeenSet { seen: [false; 54] }
    }

    fn add(&mut self, n: u8) -> bool {
        let res = !self.seen[n as usize];
        self.seen[n as usize] = true;
        res
    }

    fn done(self) -> bool {
        self.seen.iter().all(|&b| b)
    }
}

impl Clone for Permutation {
    fn clone(&self) -> Permutation {
        *self
    }
}

impl fmt::Debug for Permutation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Permutation {{ perm: {:?} }}", &self.perm[..])
    }
}

impl PartialEq for Permutation {
    fn eq(&self, other: &Permutation) -> bool {
        &self.perm[..] == &other.perm[..]
    }
}
impl Eq for Permutation {}

impl hash::Hash for Permutation {
    fn hash<H>(&self, state: &mut H)
        where H: hash::Hasher
    {
        self.perm.hash(state)
    }
}

impl Add for Permutation {
    type Output = Permutation;

    fn add(self, other: Permutation) -> Permutation {
        let mut perm = [0; 54];
        let mut seen1 = SeenSet::new();
        let mut seen2 = SeenSet::new();
        for pos in 0..54 {
            perm[pos] = other.perm[self.perm[pos] as usize];
            debug_assert!(seen1.add(self.perm[pos]));
            debug_assert!(seen2.add(other.perm[self.perm[pos] as usize]));
        }
        debug_assert!(seen1.done());
        debug_assert!(seen2.done());
        Permutation { perm: perm }
    }
}

impl Neg for Permutation {
    type Output = Permutation;

    fn neg(self) -> Permutation {
        Permutation { perm: self.applyto(&I.perm) }
    }
}

impl Sub for Permutation {
    type Output = Permutation;

    fn sub(self, other: Permutation) -> Permutation {
        self + (-other)
    }
}

impl Mul<Permutation> for u64 {
    type Output = Permutation;

    fn mul(self, other: Permutation) -> Permutation {
        let mut res = I;
        let mut cur = other;
        let mut n = self;

        while n > 0 {
            if n & 1 != 0 {
                res = res + cur;
            }
            n >>= 1;
            cur = cur + cur;
        }
        res
    }
}

impl Permutation {
    pub fn applyto<T: Copy>(&self, input: &[T; 54]) -> [T; 54] {
        let mut output = *input;
        let mut seen = SeenSet::new();

        for pos in 0..54 {
            output[self.perm[pos] as usize] = input[pos];
            debug_assert!(seen.add(self.perm[pos]));
        }
        debug_assert!(seen.done());
        output
    }
}

#[cfg_attr(rustfmt, rustfmt_skip)]
pub const I: Permutation = Permutation {
    perm: [            0,  1,  2,
                       3,  4,  5,
                       6,  7,  8,
           9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
           21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
           33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
                       45, 46, 47,
                       48, 49, 50,
                       51, 52, 53
    ]
};

#[cfg_attr(rustfmt, rustfmt_skip)]
pub const F: Permutation = Permutation {
    perm: [            0,  1,  2,
                       3,  4,  5,
                       15, 27, 39,
           9,  10, 8,  14, 26, 38, 47, 16, 17, 18, 19, 20,
           21, 22, 7,  13, 25, 37, 46, 28, 29, 30, 31, 32,
           33, 34, 6,  12, 24, 36, 45, 40, 41, 42, 43, 44,
                       11, 23, 35,
                       48, 49, 50,
                       51, 52, 53
    ]
};

#[cfg_attr(rustfmt, rustfmt_skip)]
pub const S: Permutation = Permutation {
    perm: [            0,  1,  2,
                       16, 28, 40,
                       6,  7,  8,
           9,  5,  11, 12, 13, 14, 15, 50, 17, 18, 19, 20,
           21, 4,  23, 24, 25, 26, 27, 49, 29, 30, 31, 32,
           33, 3,  35, 36, 37, 38, 39, 48, 41, 42, 43, 44,
                       45, 46, 47,
                       10, 22, 34,
                       51, 52, 53
    ]
};

#[cfg_attr(rustfmt, rustfmt_skip)]
pub const B: Permutation = Permutation {
    perm: [            33, 21, 9,
                       3,  4,  5,
                       6,  7,  8,
           51, 10, 11, 12, 13, 14, 15, 16, 0,  20, 32, 44,
           52, 22, 23, 24, 25, 26, 27, 28, 1,  19, 31, 43,
           53, 34, 35, 36, 37, 38, 39, 40, 2,  18, 30, 42,
                       45, 46, 47,
                       48, 49, 50,
                       41, 29, 17,
    ]
};

#[cfg_attr(rustfmt, rustfmt_skip)]
pub const U: Permutation = Permutation {
    perm: [            2,  5,  8,
                       1,  4,  7,
                       0,  3,  6,
           18, 19, 20, 9,  10, 11, 12, 13, 14, 15, 16, 17,
           21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
           33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
                       45, 46, 47,
                       48, 49, 50,
                       51, 52, 53
    ]
};

#[cfg_attr(rustfmt, rustfmt_skip)]
pub const E: Permutation = Permutation {
    perm: [            0,  1,  2,
                       3,  4,  5,
                       6,  7,  8,
           9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
           24, 25, 26, 27, 28, 29, 30, 31, 32, 21, 22, 23,
           33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
                       45, 46, 47,
                       48, 49, 50,
                       51, 52, 53
    ]
};

#[cfg_attr(rustfmt, rustfmt_skip)]
pub const D: Permutation = Permutation {
    perm: [            0,  1,  2,
                       3,  4,  5,
                       6,  7,  8,
           9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
           21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
           36, 37, 38, 39, 40, 41, 42, 43, 44, 33, 34, 35,
                       47, 50, 53,
                       46, 49, 52,
                       45, 48, 51
    ]
};

#[cfg_attr(rustfmt, rustfmt_skip)]
pub const L: Permutation = Permutation {
    perm: [            12, 1,  2,
                       24, 4,  5,
                       36, 7,  8,
           11, 23, 35, 45, 13, 14, 15, 16, 17, 18, 19, 6,
           10, 22, 34, 48, 25, 26, 27, 28, 29, 30, 31, 3,
           9,  21, 33, 51, 37, 38, 39, 40, 41, 42, 43, 0,
                       44, 46, 47,
                       32, 49, 50,
                       20, 52, 53
    ]
};

#[cfg_attr(rustfmt, rustfmt_skip)]
pub const M: Permutation = Permutation {
    perm: [            0,  13, 2,
                       3,  25, 5,
                       6,  37, 8,
           9,  10, 11, 12, 46, 14, 15, 16, 17, 18, 7,  20,
           21, 22, 23, 24, 49, 26, 27, 28, 29, 30, 4,  32,
           33, 34, 35, 36, 52, 38, 39, 40, 41, 42, 1,  44,
                       45, 43, 47,
                       48, 31, 50,
                       51, 19, 53
    ]
};

#[cfg_attr(rustfmt, rustfmt_skip)]
pub const R: Permutation = Permutation {
    perm: [            0,  1,  42,
                       3,  4,  30,
                       6,  7,  18,
           9,  10, 11, 12, 13, 2,  17, 29, 41, 53, 19, 20,
           21, 22, 23, 24, 25, 5,  16, 28, 40, 50, 31, 32,
           33, 34, 35, 36, 37, 8,  15, 27, 39, 47, 43, 44,
                       45, 46, 14,
                       48, 49, 26,
                       51, 52, 38
    ]
};

impl rand::Rand for Permutation {
    fn rand<R: Rng>(rng: &mut R) -> Permutation {
        let mut out = I;
        for _ in 0..50 {
            let cur = match rng.gen_range(0, 9) {
                0 => F,
                1 => S,
                2 => B,
                3 => U,
                4 => E,
                5 => B,
                6 => L,
                7 => M,
                _ => R,
            };
            out = out + cur;
        }
        out
    }
}

lazy_static! {
    pub static ref PERMUTATION_TABLE: HashMap<&'static [u8], Permutation> = hashmap!{
        &b"F"[..] => F,
        &b"F'"[..] => -F,
        &b"S"[..] => S,
        &b"S'"[..] => -S,
        &b"B"[..] => B,
        &b"B'"[..] => -B,
        &b"z"[..] => F + S - B,
        &b"z'"[..] => -F - S + B,
        &b"U"[..] => U,
        &b"U'"[..] => -U,
        &b"E"[..] => E,
        &b"E'"[..] => -E,
        &b"D"[..] => D,
        &b"D'"[..] => -D,
        &b"y"[..] => U - E - D,
        &b"y'"[..] => -U + E + D,
        &b"L"[..] => L,
        &b"L'"[..] => -L,
        &b"M"[..] => M,
        &b"M'"[..] => -M,
        &b"R"[..] => R,
        &b"R'"[..] => -R,
        &b"x"[..] => -L - M + R,
        &b"x'"[..] => L + M - R,
    };
}

impl Permutation {
    pub fn parse(s: &'static str) -> Option<Permutation> {
        let mut out = I;
        for s in s.split_whitespace() {
            match PERMUTATION_TABLE.get(s.as_bytes()) {
                Some(p) => {
                    out = out + *p;
                }
                None => return None,
            }
        }
        Some(out)
    }

    pub fn order(&self) -> usize {
        let mut cur = *self;
        for order in 1..1261 {
            if cur == I {
                return order;
            }
            cur = cur + *self;
        }
        panic!("Impossible: order cannot be larger than 1260");
    }

    pub fn from_cube(cube: Cube) -> Option<Permutation> {
        const CENTERS: [u8; 6] = [4, 22, 25, 28, 31, 49];
        const EDGES: [(u8, u8); 12] = [(1, 19), (3, 10), (5, 16), (7, 13), (21, 32), (23, 24),
                                       (26, 27), (29, 30), (46, 37), (48, 34), (50, 40), (52, 43)];
        const CORNERS: [(u8, u8, u8); 8] = [(0, 9, 20),
                                            (2, 18, 17),
                                            (6, 12, 11),
                                            (8, 15, 14),
                                            (45, 35, 36),
                                            (47, 38, 39),
                                            (51, 44, 33),
                                            (53, 41, 42)];
        let orig = Cube::default().colors;

        let mut out = [0; 54];
        let mut seen1 = SeenSet::new();
        let mut seen2 = SeenSet::new();
        let mut ok = true;

        for curloc in CENTERS.iter().cloned() {
            let curcolor = cube.colors[curloc as usize];
            for origloc in CENTERS.iter().cloned() {
                let origcolor = orig[origloc as usize];
                if origcolor == curcolor {
                    out[origloc as usize] = curloc;
                    ok &= seen1.add(origloc);
                    ok &= seen2.add(curloc);
                    break;
                }
            }
        }

        for (curloc1, curloc2) in EDGES.iter().cloned() {
            let curcolor1 = cube.colors[curloc1 as usize];
            let curcolor2 = cube.colors[curloc2 as usize];
            for (origloc1, origloc2) in
                EDGES.iter()
                    .cloned()
                    .chain(EDGES.iter().map(|&(l1, l2)| (l2, l1))) {
                let origcolor1 = orig[origloc1 as usize];
                let origcolor2 = orig[origloc2 as usize];
                if origcolor1 == curcolor1 && origcolor2 == curcolor2 {
                    out[origloc1 as usize] = curloc1;
                    out[origloc2 as usize] = curloc2;
                    ok &= seen1.add(origloc1);
                    ok &= seen1.add(origloc2);
                    ok &= seen2.add(curloc1);
                    ok &= seen2.add(curloc2);
                    break;
                }
            }
        }

        for (curloc1, curloc2, curloc3) in CORNERS.iter().cloned() {
            let curcolor1 = cube.colors[curloc1 as usize];
            let curcolor2 = cube.colors[curloc2 as usize];
            let curcolor3 = cube.colors[curloc3 as usize];
            for (origloc1, origloc2, origloc3) in
                CORNERS.iter()
                    .cloned()
                    .chain(CORNERS.iter().map(|&(l1, l2, l3)| (l2, l3, l1)))
                    .chain(CORNERS.iter().map(|&(l1, l2, l3)| (l3, l1, l2))) {
                let origcolor1 = orig[origloc1 as usize];
                let origcolor2 = orig[origloc2 as usize];
                let origcolor3 = orig[origloc3 as usize];
                if origcolor1 == curcolor1 && origcolor2 == curcolor2 && origcolor3 == curcolor3 {
                    out[origloc1 as usize] = curloc1;
                    out[origloc2 as usize] = curloc2;
                    out[origloc3 as usize] = curloc3;
                    ok &= seen1.add(origloc1);
                    ok &= seen1.add(origloc2);
                    ok &= seen1.add(origloc3);
                    ok &= seen2.add(curloc1);
                    ok &= seen2.add(curloc2);
                    ok &= seen2.add(curloc3);
                    break;
                }
            }
        }
        ok &= seen1.done();
        ok &= seen2.done();
        if ok {
            Some(Permutation { perm: out })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use rand::{self, Rng};

    #[test]
    fn test_identity() {
        assert_eq!(I, I + I);
        assert_eq!(I, I - I);
        assert_eq!(I, -I);
    }

    #[test]
    fn test_neg() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let p: Permutation = rng.gen();
            assert_eq!(I, p + (-p));
            assert_eq!(p, -(-p));
        }
    }

    #[test]
    fn test_sub() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let p1: Permutation = rng.gen();
            let p2: Permutation = rng.gen();
            assert_eq!(p1 - p2, p1 + (-p2));
        }
    }

    #[test]
    fn test_assoc() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let p1: Permutation = rng.gen();
            let p2: Permutation = rng.gen();
            let p3: Permutation = rng.gen();
            assert_eq!((p1 + p2) + p3, p1 + (p2 + p3));
        }
    }

    #[test]
    fn test_order() {
        let mut rng = rand::thread_rng();
        assert_eq!(I.order(), 1);
        for _ in 0..1000 {
            let p: Permutation = rng.gen();
            assert!(p.order() <= 1260);
        }
    }

    #[test]
    fn test_table_order() {
        for p in PERMUTATION_TABLE.values().cloned() {
            assert_eq!(p.order(), 4);
        }
    }

    #[test]
    fn test_table_neg() {
        for (name, p) in PERMUTATION_TABLE.iter() {
            let inv = if name.len() > 1 {
                PERMUTATION_TABLE.get(&[name[0]][..])
            } else {
                PERMUTATION_TABLE.get(&[name[0], b'\''][..])
            };
            assert_eq!(-(*p), *inv.unwrap());
        }
    }

    #[test]
    fn test_table_commutative() {
        let groups: HashMap<u8, u8> = hashmap!{
            b'F' => 0,
            b'S' => 0,
            b'B' => 0,
            b'z' => 0,
            b'U' => 1,
            b'E' => 1,
            b'D' => 1,
            b'y' => 1,
            b'L' => 2,
            b'M' => 2,
            b'R' => 2,
            b'x' => 2,
        };
        for (name1, p1) in PERMUTATION_TABLE.iter() {
            let group1 = groups.get(&name1[0]).unwrap();
            for (name2, p2) in PERMUTATION_TABLE.iter() {
                let group2 = groups.get(&name2[0]).unwrap();
                if group1 == group2 {
                    assert!(*p1 + *p2 == *p2 + *p1);
                } else {
                    assert!(*p1 + *p2 != *p2 + *p1);
                }
            }
        }
    }

    #[test]
    fn test_rotate() {
        assert_eq!(Permutation::parse("x y z' y'").unwrap().order(), 1);
        assert_eq!(Permutation::parse("x y").unwrap().order(), 3);
        assert_eq!(Permutation::parse("U x").unwrap().order(), 1260);
    }

    #[test]
    fn test_from_cube() {
        assert_eq!(I, Permutation::from_cube(Cube::default()).unwrap());
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let p1: Permutation = rng.gen();
            let c = Cube::default().apply(p1);
            let p2 = Permutation::from_cube(c).unwrap();
            assert_eq!(p1, p2);
        }
    }

    #[test]
    fn test_cube_assoc() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let p1: Permutation = rng.gen();
            let p2: Permutation = rng.gen();
            let c: Cube = rng.gen();
            assert_eq!(c.apply(p1).apply(p2), c.apply(p1 + p2));
        }
    }

    #[test]
    fn test_mul() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let p1: Permutation = rng.gen();
            let k = rng.gen_range(0, 30);
            let p2 = k * p1;
            let mut p3 = I;
            for _ in 0..k {
                p3 = p3 + p1;
            }

            assert_eq!(p2, p3);
        }
    }
}
