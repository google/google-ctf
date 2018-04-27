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



#[macro_use]
extern crate enum_primitive;
extern crate rand;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate maplit;
extern crate crypto;
extern crate rustc_serialize;

mod color;
mod cube;
mod permutation;
mod handshake;

use std::env;
use std::collections::HashMap;
use rustc_serialize::hex::{FromHex, ToHex};

use permutation::{I, Permutation};
use handshake::{PublicKey, SecretKey};

lazy_static! {
    pub static ref SOLVE_TABLE: HashMap<Permutation, u16> = {
        let mut map = HashMap::with_capacity(1260);

        let p0 = Permutation::parse("U x'").unwrap();
        let p1 = Permutation::parse("L y'").unwrap();

        let mut c0 = I;
        for v0 in 0..1260 {
            map.insert(c0, v0);
            c0 = c0 + p0;
        }
        assert!(map.len() == 1260);
        map
    };
}

fn solve(c: PublicKey) -> Option<SecretKey> {
    let mut c = c.key;
    let p1 = Permutation::parse("y L'").unwrap();

    for v1 in 0..1260 {
        if let Some(&v0) = SOLVE_TABLE.get(&c) {
            return Some(SecretKey {
                a: v0 as u64,
                b: v1,
            });
        }
        c = c + p1;
    }
    None
}

fn main() {

    let key1 = env::args().nth(1).unwrap();
    let key1 = PublicKey::unserialize(&key1).unwrap();

    let key2 = env::args().nth(2).unwrap();
    let key2 = PublicKey::unserialize(&key2).unwrap();

    let salt = env::args().nth(3).unwrap().from_hex().unwrap();

    if let Some(key1) = solve(key1) {
        println!("{}", key1.handshake(key2, &salt).to_hex());
    } else if let Some(key2) = solve(key2) {
        println!("{}", key2.handshake(key1, &salt).to_hex());
    } else {
        println!("Cannot solve either of the keys");
    }
}
