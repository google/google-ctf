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



use std::ops::{Add, Mul};

#[derive(Clone)]
struct Ge([u8; 32]);

impl Ge {
    fn mulx(&mut self) {
        let reduce: [u8; 32] = if self.0[31] & 0x08 != 0 {
            [0x09, 0x82, 0x3b, 0xad, 0x5d, 0xc5, 0xea, 0xda, 0x33, 0xa6, 0x1b, 0x93, 0x69, 0x82,
             0xd3, 0xca, 0x18, 0x3b, 0x98, 0x18, 0x48, 0xe8, 0x66, 0xd2, 0x17, 0x2d, 0xd3, 0xe5,
             0xaa, 0xd3, 0x2d, 0x1b]
        } else {
            [0; 32]
        };

        let mut carry = 0;
        for n in 0..32 {
            let next = if self.0[n] & 0x80 != 0 { 1 } else { 0 };
            self.0[n] = reduce[n] ^ (self.0[n] << 1) ^ carry;
            carry = next;
        }
    }
}

impl<'a> Add<&'a Ge> for Ge {
    type Output = Ge;
    fn add(mut self, other: &Ge) -> Ge {
        for n in 0..32 {
            self.0[n] ^= other.0[n];
        }
        self
    }
}

impl<'a> Mul<&'a Ge> for Ge {
    type Output = Ge;
    fn mul(mut self, b: &Ge) -> Ge {
        let mut r = Ge([0; 32]);
        for n in 0..32 {
            for k in 0..8 {
                if b.0[n] & (1 << k) != 0 {
                    r = r + &self;
                }
                self.mulx();
            }
        }
        r
    }
}

impl Ge {
    fn exp(mut self, e: &[u8; 32]) -> Ge {
        let mut r = Ge([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0]);
        for n in 0..32 {
            for k in 0..8 {
                if e[n] & (1 << k) != 0 {
                    r = r * &self;
                }
                let self_ = self.clone();
                self = self * &self_;
            }
        }
        r
    }
}

pub fn crypto_scalarmult(n: &[u8; 32], p: &[u8; 32]) -> [u8; 32] {
    Ge(*p).exp(&n).0
}

pub fn crypto_scalarmult_base(n: &[u8; 32]) -> [u8; 32] {
    crypto_scalarmult(n,
                      &[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0])
}
