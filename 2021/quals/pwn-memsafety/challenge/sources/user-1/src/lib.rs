/*
    Copyright 2021 Google LLC

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/
#![no_std]
use proc_sandbox::sandbox;

#[sandbox]
pub mod user {
    static FLAG: &'static str = "CTF{s4ndb0x1n9_s0urc3_1s_h4rd_ev3n_1n_rus7}";
    use prelude::{mem::ManuallyDrop, Service, Box, String};
    pub struct State(ManuallyDrop<String>);
    impl State {
        pub fn new() -> Box<dyn Service> {
            Box::new(State(ManuallyDrop::new(String::from(FLAG))))
        }
    }
    impl Service for State {
       fn handle(&mut self, _: &str) {}
    }
}
