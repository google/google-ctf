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



extern crate rand;
extern crate rustc_serialize;

use rand::Rng;
use rustc_serialize::hex::ToHex;

mod kex;

fn main() {
    let mut rng = rand::thread_rng();
    let our_secret_key: [u8; 32] = rng.gen();
    let our_public_key = kex::crypto_scalarmult_base(&our_secret_key);
    println!("{}", our_public_key.to_hex());
}
