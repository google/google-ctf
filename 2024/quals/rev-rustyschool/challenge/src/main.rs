// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//////////////////////////////////////////////////////////////////////////////////////////
//                                                                                      //
//                           GCTF'24: 🦀 Rusty School 🦀 (RE)                           //
//                                                                                      //
// Build the challenge as: `cargo build --bin rustyschool --release`                    //
//////////////////////////////////////////////////////////////////////////////////////////
use std::env;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::iter::once;
use rand::Rng;
use md5::{Md5, Digest};
use sha1::Sha1;
use num_bigint::BigUint;


/// Custom println! MACRO that disables print statements in release builds.
/// To execute the program with the debug statements:
///     `cargo run --features debug_mode -- sample.plaintext`
macro_rules! dbg_println {
    ($($rest:tt)*) => {
        #[cfg(feature = "debug_mode")]
        std::println!($($rest)*)
    }
}


/// Round funcion: F(a, b) = MD5(a || b)[:12].
#[inline(always)]
fn f(a: &[u8], b: &[u8]) -> Vec<u8> {
    let c: Vec<u8> = vec![a.to_owned(), b.to_owned()].concat();
    Md5::digest(c).as_slice()[..12].to_vec()
}


/// Round funcion: G(a, b) = SHA1(a || b)[:12].
#[inline(always)]
fn g(a: &[u8], b: &[u8]) -> Vec<u8> {
    let c: Vec<u8> = vec![a.to_owned(), b.to_owned()].concat();
    Sha1::digest(c).as_slice()[..12].to_vec()
}


/// Galois Field addition (or XOR of vectors).
#[inline(always)]
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| *a ^ *b).collect()
}


/// Galois Field multiplication. Multiplies 2 numbers in the GF(2^16) by the modulo
/// irreducible polynomial: x^16 + x^5 + x^3 + x + 1 = 0 (or 0x1002B).
#[inline(always)]
fn gfmul(mut a: u16, mut b: u16) -> u16 {
    let mut p: u16 = 0;
    while a != 0 && b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }

        if a & 0x8000 != 0 {
            a = (a << 1) ^ 0x0002b;
        } else {
            a <<= 1;
        }

        b >>= 1;
    }

    p
}


/// Key schedule algorithm. Given a round key `key_r` it generates the 2 key schedules
/// A and B (`ks_a`, `ks_b`) for the current round in Feistel Network using Galois
/// Fields transformations.
///
/// NOTE: We want key_schedule to take ownership of the `key_r`.
#[inline(always)]
fn key_schedule(key_r: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // First convert the 12-byte vector, into a 6-word vector (6 subkeys).
    let mut subkeys: Vec<u16> = Vec::new();
    for i in (0..12).step_by(2) {
        subkeys.push(((key_r[i + 1] as u16) << 8) | (key_r[i] as u16));
    }

    dbg_println!("Round key: {:02x?}", key_r);
    dbg_println!("Subkeys: {:04x?}", subkeys);

    // Compute the new keys using Galois Fields.
    let k_a: Vec<u16> = (0..6).map(|i|
        gfmul(subkeys[i], subkeys[(i + 1) % 6]) ^ subkeys[(i + 4) % 6]
    ).collect();
    let k_b: Vec<u16> = (0..6).map(|i|
        gfmul(subkeys[(i + 2) % 6], subkeys[(i + 3) % 6]) ^ subkeys[(i + 5) % 6]
    ).collect();
    
    dbg_println!("Derived Key A: {:04x?}", k_a);
    dbg_println!("Derived Key B: {:04x?}", k_b);

    // Convert 6-word vectors back to 12-byte vectors.
    /*
    // The simple way:
    let mut ks_a: Vec<u8> = Vec::new();
    let mut ks_b: Vec<u8> = Vec::new();
    for i in 0..6 {
        ks_a.push((k_a[i] & 0xFF) as u8);
        ks_a.push((k_a[i] >> 8) as u8);

        ks_b.push((k_b[i] & 0xFF) as u8);
        ks_b.push((k_b[i] >> 8) as u8);
    }
    */

    // The rustacean's way (preferred to complicate reversing):
    let ks_a: Vec<u8> = k_a.clone().into_iter().zip(k_a.into_iter()).flat_map(|x|
        once((x.0 & 0xff) as u8).chain(once((x.1 >> 8) as u8))
    ).collect();
    let ks_b: Vec<u8> = k_b.clone().into_iter().zip(k_b.into_iter()).flat_map(|x|
        once((x.0 & 0xff) as u8).chain(once((x.1 >> 8) as u8))
    ).collect();

    dbg_println!("Key Schedule A: {:02x?}", ks_a);
    dbg_println!("Key Schedule B: {:02x?}", ks_b);

    (ks_a, ks_b)
}


/// Block encryption routine. Encrypts a single 48-byte block and returns a 60-byte block
/// (48-bytes for ciphertext + 12-bytes for key).
#[inline(always)]
fn encr_blk(plain: &[u8], key: &[u8]) -> Result<Vec<u8>, &'static str> {
    // Split input plaintext into 4 12-byte chunks.
    let mut p0 = plain[..12].to_vec();
    let mut p1 = plain[12..24].to_vec();
    let mut p2 = plain[24..36].to_vec();
    let mut p3 = plain[36..].to_vec();

    let mut key_r = key.to_vec();
    let mut cipher = Vec::new();

    // Do 12 rounds of the modified Feistel Network.
    for _i in 0..12 {
        dbg_println!("--------------- Round #{} ----------", _i);

        let (ks1_a, ks1_b) = key_schedule(&key_r);

        // Compute: A*(B + D) + C^B  mod N for the last route (D) of the network.
        let a = BigUint::from_bytes_le(&p0);
        let b = BigUint::from_bytes_le(&p1);
        let c = BigUint::from_bytes_le(&p2);
        let d = BigUint::from_bytes_le(&p3);

        dbg_println!("Bigint A: {:x?}", a);
        dbg_println!("Bigint B: {:x?}", b);
        dbg_println!("Bigint C: {:x?}", c);
        dbg_println!("Bigint D: {:x?}", d);

        // def gen_rand_prime(nbits=512):
        //   while True:
        //     p = random_prime(2^nbits - 1, false, 2^(nbits - 1))
        //     if ZZ((p - 1)/2).is_prime():
        //       return p
        //
        // prime = gen_rand_prime(12*8+1)
        // print(f'prime: {prime} | 0x{prime:X}')
        //
        // We choose a high prime such that D < N:
        //   prime: 79160129948973046149879599747 | 0xFFC7B98B3EDDBD9EA6929283
        //
        // If that's not the case we must throw an exception and try again.
        let n = BigUint::parse_bytes(b"79160129948973046149879599747", 10).unwrap();

        if d >= n {
            // D is too big, so we won't be able to recover it. Throw an error
            // and try again.
            return Err("Prime too small!");
        }

        // Compute output for the current round.
        let c0 = p2.to_vec();
        let c1 = xor(&f(&ks1_a, &p2), &p0);
        let c2 = (a*(&b + d) + c.modpow(&b, &n)) % n;
        let c3 = xor(&g(&ks1_b, &p2), &p1);

        dbg_println!("Bigint R: {:x?}", c2);
        let mut c2 = c2.to_bytes_le();

        while c2.len() < 12 {
            c2.insert(c2.len(), 0);  // Ensure c2 is always 12 bytes long.
        }

        p0 = c0;
        p1 = c1;
        p2 = c2;
        p3 = c3;
       
        key_r = ks1_a;  // Update round key.

        // Update the final ciphertext output.
        cipher.clear();
        cipher.extend(&p0);
        cipher.extend(&p1);
        cipher.extend(&p2);
        cipher.extend(&p3);
        cipher.extend(ks1_b);

        dbg_println!("Ciphertext: {:x?}", cipher);
    }

    Ok(cipher)
}


/// Rusty School starts from here.
fn main() {
    println!("🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀");
    println!("🦀   Rusty School Encryption Tool   🦀");
    println!("🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀");

    // We intentionally put everything in one function to make reversing harder.
    let args: Vec<String> = env::args().collect();
    let filename = match args.len() {
        // We need exactly one argument (argc = 2).
        2 => {
            &args[1]
        },
        _ => {
            // If you manage to pass 0 arguments and crash this,
            // congratulations.
            println!("usage: {} <filename_to_encrypt>", args[0]);
            return
        }
    };

    println!("Loading file to encrypt: {}", filename);

    let mut fin = File::open(filename).expect("Cannot open file");
    let mut fout = File::create(format!("{filename}.encrypted")).expect("Cannot create file");
    let mut rng = rand::thread_rng();
    let mut _blk_cnt = 0;

    loop {
        // We initialize buffer with 1s instead of 0s, to ensure the modular
        // equation always has a solution.
        let mut buffer = vec![1; 48];
        let len = fin.read(&mut buffer).expect("Buffer overflow");

        dbg_println!("================================================================");
        dbg_println!("Encrypting block #{}: {:?}, {}", _blk_cnt, buffer, len);

        // TODO(ispo): Assign each block encryption to a thread.
        loop { 
            let key: Vec<u8> = (0..12).map(|_| rng.gen_range(0..=255)).collect();

            let cipher = match encr_blk(&buffer, &key) {
                Ok(cipher) => cipher,
                Err(err) => {
                    println!("Got error: {}", err);
                    continue; // Try again with another key.
                }
            };
            
            dbg_println!("Ciphertext: {:x?}", cipher);
            fout.write_all(&cipher).expect("Cannot write to file");
            break;
        }

        if len < 48 {
            break;
        }

        _blk_cnt += 1;
    }

    println!("Encryption completed :)");
}
