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

use core::ptr::write_volatile;

const Z80_RAM_BASE: u32 = 0x00a0_0000;
const Z80_RAM_SIZE: u32 = 0x2000;
const Z80_CTRL_BASE: u32 = 0x00a1_1100;
const Z80_BUS_REQ: *mut u16 = Z80_CTRL_BASE as _;
const Z80_RESET: *mut u16 = (Z80_CTRL_BASE + 0x100) as _;

/// Request the bus from the Z80.
///
/// This is required to access Z80 RAM without causing the 68k to hang.
pub fn request_bus(r: bool) {
    unsafe {
        if r {
            write_volatile(Z80_BUS_REQ, 0x100);
        } else {
            write_volatile(Z80_BUS_REQ, 0);
        }
    }
}

/// Halt the Z80.
///
/// This needs to be toggled on and then off to trigger a reset. The Z80
/// memory cannot be accessed from the 68k whilst the Z80 is resetting.
pub fn halt(r: bool) {
    unsafe {
        if r {
            write_volatile(Z80_RESET, 0);
        } else {
            write_volatile(Z80_RESET, 0x100);
        }
    }
}

/// Reset the Z80.
///
/// This is required after uploading a program.
pub fn reset() {
    request_bus(true);
    halt(false);
    request_bus(false);
}

/// Access the Z80's RAM.
///
/// The bus must be requested for accesses into this slice to be safe,
/// though it is safe to call this function beforehand.
///
/// # Safety
/// Grants direct access to the ram, as slice.
/// If the RAM changes, Rusts' mutability guarantees may not hold
#[must_use]
pub unsafe fn ram() -> &'static mut [u8] {
    core::slice::from_raw_parts_mut(Z80_RAM_BASE as _, Z80_RAM_SIZE as usize)
}
