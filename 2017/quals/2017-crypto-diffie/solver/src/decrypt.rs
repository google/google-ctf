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



extern crate rustc_serialize;
extern crate gmp;
extern crate rand;
extern crate crypto;
#[macro_use]
extern crate arrayref;

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use crypto::blake2b::Blake2b;
use crypto::chacha20poly1305::ChaCha20Poly1305;
use crypto::digest::Digest;
use crypto::aead::AeadDecryptor;

#[allow(unused_imports)]
use rustc_serialize::hex::ToHex;

pub mod kex;
pub mod fast_kex;

fn decrypt(input_data: &[u8]) -> Vec<u8> {
    let (pubkey1_data, input_data) = input_data.split_at(32);
    let (pubkey2_data, input_data) = input_data.split_at(32);
    let (nonce_data, input_data) = input_data.split_at(8);
    let (tag_data, cipher_data) = input_data.split_at(16);

    let public_key = *array_ref!(pubkey1_data, 0, 32);
    let our_public_key = *array_ref!(pubkey2_data, 0, 32);
    let nonce = *array_ref!(nonce_data, 0, 8);

    let our_secret_key = fast_kex::solve_dlp(&our_public_key);
    let shared_key = kex::crypto_scalarmult(&our_secret_key, &public_key);

    let mut hash = Blake2b::new(32);
    hash.input(public_key.as_ref());
    hash.input(our_public_key.as_ref());
    hash.input(shared_key.as_ref());
    let mut shared_key: [u8; 32] = [0; 32];
    hash.result(&mut shared_key);

    let mut decryptor = ChaCha20Poly1305::new(&shared_key, &nonce, &[]);
    let mut output_data = vec![0; cipher_data.len()];
    assert!(decryptor.decrypt(cipher_data, &mut output_data, tag_data));

    output_data

}

fn main() {
    let mut args = env::args();
    let filename = args.nth(1).unwrap();
    let mut input_file = File::open(&filename).unwrap();
    let mut input = Vec::new();
    input_file.read_to_end(&mut input).unwrap();

    let output = decrypt(&input);
    let mut output_file = File::create(format!("{}.dec", filename)).unwrap();
    output_file.write_all(&output).unwrap();
}
