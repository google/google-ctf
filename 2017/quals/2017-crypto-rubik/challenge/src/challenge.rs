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

use rand::Rng;
use std::collections::HashMap;
use handshake::{PublicKey, SecretKey};
use std::io;
use rustc_serialize::hex::ToHex;

pub mod color;
pub mod cube;
pub mod permutation;
pub mod handshake;

struct State {
    is_logged_in: bool,
    users: HashMap<String, PublicKey>,
    stdin: io::Stdin,
}

impl State {
    fn new() -> State {
        let mut rng = rand::thread_rng();
        let mut users = HashMap::new();
        users.insert("admin".to_owned(), PublicKey { key: rng.gen() });
        State {
            is_logged_in: false,
            users: users,
            stdin: io::stdin(),
        }
    }

    fn line(&mut self) -> String {
        let mut line = String::new();
        self.stdin.read_line(&mut line).unwrap();
        line.trim().to_owned()
    }

    fn public_key_service(&mut self) {
        println!("What is your value of a?");
        let a = match self.line().parse::<u64>() {
            Ok(a) => a,
            Err(_) => {
                println!("Bad value");
                return;
            }
        };
        println!("What is your value of b?");
        let b = match self.line().parse::<u64>() {
            Ok(a) => a,
            Err(_) => {
                println!("Bad value");
                return;
            }
        };
        let secret = SecretKey { a: a, b: b };
        println!("Your public key is ({} * \"U x'\" + {} * \"L y'\") ==\n{}\n",
                 a,
                 b,
                 secret.to_public().serialize());
    }

    fn register(&mut self) {
        println!("What username do you want to register?");
        let username = self.line();
        if self.users.get(&username).is_some() {
            println!("User already exists");
            return;
        }
        println!("What public key do you want to register?");
        let key = self.line();
        if let Some(key) = PublicKey::unserialize(&key) {
            self.users.insert(username, key);
            println!("User registered!\n");
        } else {
            println!("Bad public key\n");
        }
    }

    fn login(&mut self) {
        println!("What user do you want to log in as?");
        let username = self.line();
        let yourkey = match self.users.get(&username) {
            Some(key) => *key,
            None => {
                println!("No such user");
                return;
            }
        };
        let mut rng = rand::os::OsRng::new().unwrap();
        let mykey = SecretKey {
            a: rng.gen_range(10, 1250),
            b: rng.gen_range(10, 1250),
        };
        let salt: [u8; 8] = rng.gen();
        println!("My public key is:\n{}\n", mykey.to_public().serialize());
        println!("Please give me the result of:");
        println!("mykey.handshake(yourkey, {:?}.from_hex().unwrap()).to_hex()",
                 salt.to_hex());

        let their_result = self.line();
        let my_result = mykey.handshake(yourkey, &salt).to_hex();

        if my_result == their_result {
            self.is_logged_in = true;
            println!("Your are now logged in!");
            if username == "admin" {
                let flag = include_str!("flag.txt");
                println!("Here is the flag: {}", flag);
            }
        } else {
            println!("No, the correct answer was:\n{}\n", my_result);
        }
    }

    fn list(&mut self) {
        println!("List of registered users:");
        for (user, key) in self.users.iter() {
            println!("Username: {}", user);
            println!("Key: {}", key.serialize());
            println!();
        }
    }

    fn menu(&mut self) {
        loop {
            println!("You have the following options:");
            println!("1) Public key service");
            println!("2) Register");
            println!("3) Login");
            if self.is_logged_in {
                println!("4) List users");
            }
            println!("q) Quit");

            let line = self.line();
            match line.as_ref() {
                "1" => self.public_key_service(),
                "2" => self.register(),
                "3" => self.login(),
                "4" if self.is_logged_in => self.list(),
                "q" => return,
                line => println!("Unknown option {:?}", line),
            }
        }
    }
}

fn main() {
    println!("Welcome to the Rubik's cube authentication server!");
    println!();

    State::new().menu();
}
