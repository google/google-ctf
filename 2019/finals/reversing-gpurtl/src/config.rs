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

use crate::glsl::lut::BLOCK_SIZE;

use arrayvec::ArrayVec;
use nom::number::streaming::{be_u32, be_u16};
use nom::{count, do_parse, exact, named, tag};

use crate::glsl::lut::ty::Programming;

named!(
    programming<Programming>,
    do_parse!(
        a: be_u32
            >> b: be_u32
            >> (Programming {
                a,
                b
            })
    )
);

pub type ProgrammingBlock = ArrayVec<[Programming; BLOCK_SIZE]>;

named!(
    programming_block<ProgrammingBlock>,
    do_parse!(ps: count!(programming, BLOCK_SIZE) >> (ps.into_iter().collect()))
);

pub struct Config {
    blocks: Vec<ProgrammingBlock>,
    jumps: Vec<u32>,
    port_bits: usize,
}

named!(
    config<Config>,
    do_parse!(
        tag!("gpurtlPC")
            >> block_count: be_u32
            >> port_bits: be_u16
            >> jump_count: be_u16
            >> blocks: count!(programming_block, block_count as usize)
            >> jumps: count!(be_u32, jump_count as usize)
            >> (Config {
                blocks,
                jumps,
                port_bits: port_bits as usize
            })
    )
);

impl Config {
    pub fn new(data: &[u8]) -> Self {
        exact!(data, config).expect("parsing config").1
    }

    pub fn size_blocks(&self) -> usize {
        self.blocks.len()
    }

    pub fn size(&self) -> usize {
        self.blocks.len() * BLOCK_SIZE
    }

    pub fn port_bits(&self) -> usize {
        self.port_bits
    }

    pub fn data(&self) -> impl Iterator<Item = &Programming> {
        self.blocks.iter().flatten()
    }

    pub fn jump_size(&self) -> usize {
        self.jumps.len()
    }

    pub fn jumps<'a>(&'a self) -> impl ExactSizeIterator<Item = u32> + 'a {
        self.jumps.iter().copied()
    }
}
