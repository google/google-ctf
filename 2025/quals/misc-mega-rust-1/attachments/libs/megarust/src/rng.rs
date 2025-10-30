// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(target_arch = "m68k")]
pub struct PseudoRng {
    current_rand: u16,
}

#[cfg(target_arch = "m68k")]
impl PseudoRng {
    // Thank you Stephane Dallongeville!
    #[must_use]
    pub fn from_seed(seed: u16) -> PseudoRng {
        PseudoRng {
            current_rand: seed ^ 0xD94B, // XOR with some val to avoid 0
        }
    }

    /// Returns the next random [`u16`] value
    #[cfg(target_arch = "m68k")]
    pub fn random(&mut self) -> u16 {
        use core::ptr::read_volatile;
        const GFX_HVCOUNTER_PORT: *const u16 = 0x00C0_0008 as _;
        // SAFETY
        // The read_volatile call is guaranteed ONLY on the Sega Mega Drive. The horizontal/vertical
        // video sync counter is a "port" that is mapped directly into the system address space. It
        // is to my knowledge always initialized, so GFX_HVCOUNTER_PORT can never be a null
        // reference.
        unsafe {
            // https://github.com/Stephane-D/SGDK/blob/908926201af8b48227be4dbc8fbb0d5a18ac971b/src/tools.c#L36
            let hv_counter = read_volatile(GFX_HVCOUNTER_PORT);
            self.current_rand ^= (self.current_rand >> 1) ^ hv_counter;
            self.current_rand ^= self.current_rand << 1;
            self.current_rand
        }
    }
}
