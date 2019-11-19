#![allow(non_snake_case)]
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


extern crate base64;
extern crate curve25519_dalek;
extern crate mersenne_twister;
extern crate rand;
extern crate sha2;
extern crate byteorder;

use byteorder::{LittleEndian, ReadBytesExt};
use curve25519_dalek::montgomery::*;
use curve25519_dalek::scalar::*;
use mersenne_twister::*;
use rand::*;
use sha2::{Digest, Sha512};
use std::io;

const SEED_SIZE: usize = 312;
type Seed = [u64; SEED_SIZE];

fn xor(a: Seed, b: Seed) -> Seed {
    let mut result: Seed = [0u64; SEED_SIZE];
    for i in 0..SEED_SIZE {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

fn generate_random_point(rng: &mut MersenneTwister) -> MontgomeryPoint {
    let mut point = [0u8; 32];
    for i in 0..32 {
        point[i] = rng.next_u64() as u8;
    }
    return MontgomeryPoint(point);
}

fn secure_random_scalar() -> Scalar {
    let mut point = [0u8; 32];
    thread_rng().fill_bytes(&mut point);
    return Scalar::from_bytes_mod_order(point);
}

fn ReadPoint(stdin: &mut io::Stdin) -> MontgomeryPoint {
    let mut message = String::new();
    stdin.read_line(&mut message).unwrap();
    message = message.trim().to_string();
    let decoded = base64::decode(&message).unwrap();
    if decoded.len() != 32 {
        panic!("The point must be 32-bytes long, got: {:?}", decoded.len());
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    return MontgomeryPoint(bytes);
}

fn ReadMessage(stdin: &mut io::Stdin) -> (Seed, Vec<u8>) {
    let mut message = String::new();
    stdin.read_line(&mut message).unwrap();
    message = message.trim().to_string();
    let decoded = base64::decode(&message).unwrap();
    let mut rdr = std::io::Cursor::new(decoded.clone());
    let mut result = [0u64; SEED_SIZE];
    for i in 0..std::cmp::min(decoded.len()/8 , SEED_SIZE) {
        result[i] = rdr.read_u64::<LittleEndian>().unwrap();
    }
    (result, decoded)
}

fn ComputeHashPoint(A: MontgomeryPoint, R: MontgomeryPoint, message: Seed) -> Scalar {
    let mut hasher = Sha512::default();
    hasher.input(R.to_bytes());
    hasher.input(A.to_bytes());
    let elements = message
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
    hasher.input(elements.as_slice().join(","));
    return Scalar::from_hash(hasher);
}

const NUM_ITERATIONS: usize = 2;

fn instance(flag: String) {
    // Use a secure RNG for starting the mersenne twister and generating the secret key.
    let s = secure_random_scalar();
    let mut seed: Seed = [0u64; SEED_SIZE];
    let mut trng = thread_rng();
    for i in 0..SEED_SIZE {
        seed[i] = trng.next_u64();
    }
    for _ in 0..NUM_ITERATIONS {
        let mut rng: MersenneTwister = SeedableRng::from_seed(&seed[..]);
        let B = generate_random_point(&mut rng);
        let mut stdin = io::stdin();
        println!("B: {}", base64::encode(&B.to_bytes()));
        let A = B * s;
        let R = ReadPoint(&mut stdin);
        let S = ReadPoint(&mut stdin);
        let (message, textual_message) = ReadMessage(&mut stdin);
        // Use the message to provide better entropy for the system.
        seed = xor(seed, message);
        let hash = ComputeHashPoint(A, R, message);
        if ed25519_check(A, S, R, hash)
            && textual_message.starts_with(b"Give me the flag, you bloody scoundrel!")
        {
            println!("Good job, here's your flag: {}", flag);
            return;
        } else {
            println!("BOO, try again");
        }
    }
    println!("Out of tries bud");
}

fn ed25519_check(A: MontgomeryPoint, S: MontgomeryPoint, R: MontgomeryPoint, h: Scalar) -> bool {
    if let Some(Re) = R.to_edwards(0) {
        if let Some(hAe) = (h * A).to_edwards(0) {
            return (Re + hAe).to_montgomery() == S;
        }
    }
    return false;
}

fn main() {
    let flag = std::fs::read_to_string("flag.txt").expect("Failed to read flag.");
    instance(flag);
}
