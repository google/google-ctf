// Copyright 2019 Google LLC
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
extern crate structure;
extern crate base64;
extern crate memmap;
extern crate rand;

use rand::*;

const NN: usize = 312;
const BITS: usize = 64;
const PSIZE: usize = NN * BITS;
const NSAMPLES: usize = (NN + 2) * BITS;
const MM: usize = NN / 2;
const K: usize = 1337;

fn jumble(key: [u64; NN]) -> [u64; NN] {
    let mut state = [0u64; NN];
    let mut i = 1;
    for _ in 0..K * (NN - 1) {
        // Replace the slow + and * operations with something faster.
        state[i] = state[i]
            ^ ((state[i - 1] ^ (state[i - 1] >> 62)) ^
                ((state[i - 1] >> 32) & 0xdeadbeefu64));
        // state[i-1] ^ Wrapping(key[i]) ^
        i += 1;
        if i >= NN {
            state[0] ^= state[NN - 1];
            i = 1;
        }
    }
    return state;
}

use std::fs::File;
use std::io::prelude::*;

use memmap::MmapMut;

fn ropen(fname: String) -> MmapMut {
    use std::fs::OpenOptions;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&fname)
        .expect("failed to open file");
    file.set_len((NSAMPLES * NN * 8) as u64)
        .expect("failed to set length");

    return unsafe { MmapMut::map_mut(&file).expect("failed to map") };
}

fn main() {
    let mut rng = thread_rng();
    let mut startb = ropen("start".to_string());
    let mut endb = ropen("end".to_string());
    for j in 0..NSAMPLES {
        if j % 100 == 0 {
            println!("{:?}", j);
        }
        let mut buffer = [0u64; NN];
        for i in 0..NN {
            buffer[i] = rng.next_u64();
            for k in 0..8 {
                startb[j * NN * 8 + i * 8 + k] = (buffer[i] >> k * 8) as u8;
            }
        }
        let end = jumble(buffer);
        for i in 0..NN {
            for k in 0..8 {
                endb[j * NN * 8 + i * 8 + k] = (end[i] >> k * 8) as u8;
            }
        }
    }
    startb.flush().expect("failed to flush");
    endb.flush().expect("failed to flush");
}
