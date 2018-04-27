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
extern crate arrayref;
extern crate crypto;
extern crate rand;
extern crate rustc_serialize;

use crypto::aead::AeadEncryptor;
use crypto::blake2b::Blake2b;
use crypto::chacha20poly1305::ChaCha20Poly1305;
use crypto::digest::Digest;
use rand::Rng;
use rustc_serialize::hex::{FromHex, ToHex};
use std::env;
use std::fs::File;
use std::io::{Read, Write};

pub mod kex;

fn encrypt(input_data: &[u8], public_key: &[u8; 32]) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let our_secret_key: [u8; 32] = rng.gen();
    let our_public_key = kex::crypto_scalarmult_base(&our_secret_key);
    let shared_key = kex::crypto_scalarmult(&our_secret_key, &public_key);

    let mut hash = Blake2b::new(32);
    hash.input(public_key.as_ref());
    hash.input(our_public_key.as_ref());
    hash.input(shared_key.as_ref());
    let mut shared_key: [u8; 32] = [0; 32];
    hash.result(&mut shared_key);

    let nonce: [u8; 8] = rng.gen();
    let mut encryptor = ChaCha20Poly1305::new(&shared_key, &nonce, &[]);

    let mut output_data = vec![0; 32 + 32 + 8 + 16 + input_data.len()];

    {
        let (pubkey1_data, output_data) = output_data.split_at_mut(32);
        let (pubkey2_data, output_data) = output_data.split_at_mut(32);
        let (nonce_data, output_data) = output_data.split_at_mut(8);
        let (tag_data, cipher_data) = output_data.split_at_mut(16);

        pubkey1_data.copy_from_slice(public_key.as_ref());
        pubkey2_data.copy_from_slice(our_public_key.as_ref());
        nonce_data.copy_from_slice(nonce.as_ref());

        encryptor.encrypt(input_data, cipher_data, tag_data);
    }

    output_data
}

fn main() {
    let mut args = env::args();
    let mut pubkey = args.nth(1).unwrap();
    while pubkey.len() < 64 {
        pubkey.push('0');
    }
    let pubkey = pubkey.from_hex().unwrap();
    let pubkey = array_ref!(pubkey, 0, 32);
    let filename = args.next().unwrap();

    println!("Encrypting file {} for pubkey {}",
             filename,
             pubkey.to_hex());
    let mut input_file = File::open(&filename).unwrap();
    let mut input = Vec::new();
    input_file.read_to_end(&mut input).unwrap();

    let output = encrypt(&input, &pubkey);
    let mut output_file = File::create(format!("{}.enc", filename)).unwrap();
    output_file.write_all(&output).unwrap();
}
