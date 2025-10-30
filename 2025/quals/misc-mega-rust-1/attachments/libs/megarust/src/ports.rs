#![allow(dead_code)]
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

use core::ptr::read_volatile;
use core::ptr::write_volatile;

const IO_BASE: u32 = 0xa1_0000;
const IO_DATA: *mut u8 = (IO_BASE + 3) as _;
const IO_CTRL: *mut u8 = (IO_BASE + 9) as _;
const IO_TX: *mut u8 = (IO_BASE + 0xf) as _;
const IO_RX: *mut u8 = (IO_BASE + 0x11) as _;
const IO_SCTRL: *mut u8 = (IO_BASE + 0x13) as _;

fn read_reg_2(base: *mut u8, idx: u8) -> u8 {
    unsafe { read_volatile(base.offset(idx as isize)) }
}

fn write_reg_2(base: *mut u8, idx: u8, v: u8) {
    unsafe {
        write_volatile(base.offset(idx as isize), v);
    }
}

fn read_reg_6(base: *mut u8, idx: u8) -> u8 {
    unsafe { read_volatile(base.offset((idx * 6) as isize)) }
}

fn write_reg_6(base: *mut u8, idx: u8, v: u8) {
    unsafe {
        write_volatile(base.offset((idx * 6) as isize), v);
    }
}

/// A configurable baud rate for serial port operation.
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum Baud {
    B4800 = 0b00,
    B2400 = 0b01,
    B1200 = 0b10,
    B300 = 0b11,
}

/// The current status of the serial port.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SerialStatus(u8);

impl SerialStatus {
    /// Returns true if the serial port is ready to receive.
    pub fn is_rx_ready(self) -> bool {
        (self.0 & 2) != 0
    }

    /// Returns true if a receive error has occurred.
    pub fn has_rx_error(self) -> bool {
        (self.0 & 4) != 0
    }

    /// Returns true if the TX buffer is full.
    ///
    /// No more bytes can be queued in this state.
    pub fn is_tx_full(self) -> bool {
        (self.0 & 1) != 0
    }

    /// Returns true if this port is configured to raise an interrupt
    /// when there is data to read.
    pub fn rx_interrupt_enabled(self) -> bool {
        (self.0 & 8) != 0
    }

    /// Returns true if this port has serial output mode enabled.
    pub fn serial_tx(self) -> bool {
        (self.0 & 0x10) != 0
    }

    /// Returns true if this port is configured for receiving via serial mode.
    pub fn serial_rx(self) -> bool {
        (self.0 & 0x20) != 0
    }

    /// Returns the current configured baud rate of this serial port.
    pub fn baud(self) -> Baud {
        match self.0 >> 6 {
            0b00 => Baud::B4800,
            0b01 => Baud::B2400,
            0b10 => Baud::B1200,
            _ => Baud::B300,
        }
    }
}

/// A representation of one of the 3 IO ports on the Mega Drive.
pub(crate) struct IOPort(u8);

impl IOPort {
    /// Set the directions of the pins on this IO port.
    ///
    /// A one indicates the pin is used as output.
    pub fn set_pin_directions_raw(&self, directions: u8, enable_int: bool) {
        let intr = if enable_int { 0x80 } else { 0 };
        write_reg_2(IO_CTRL, self.0, intr | (directions & 0x7f));
    }

    /// Set the values of output pins.
    ///
    /// Any other specified pin values are ignored.
    pub fn set_pins(&self, values: u8) {
        write_reg_2(IO_DATA, self.0, values);
    }

    /// Get the value of all of the pins.
    ///
    /// Output pins show the value they were last set to.
    pub fn get_pins(&self) -> u8 {
        read_reg_2(IO_DATA, self.0)
    }

    /// Configure serial operation of this IO port.
    ///
    /// `sin` uses the serial converter for input.
    /// `sout` uses the serial converter for output.
    /// `rint` enables the serial interrupt for this port.
    pub fn configure_serial(&self, sin: bool, sout: bool, rint: bool, baud: Baud) {
        let mut v = (baud as u8) << 6;

        if sin {
            v |= 0x20;
        }

        if sout {
            v |= 0x10;
        }

        if rint {
            v |= 0x80;
        }

        // The 3 lowest bits are status bits.
        write_reg_6(IO_SCTRL, self.0, v);
    }

    /// Read the serial status from the IO port.
    pub fn serial_status_raw(&self) -> u8 {
        read_reg_6(IO_SCTRL, self.0)
    }

    /// Read a single byte from the serial port.
    pub fn serial_read(&self) -> u8 {
        read_reg_6(IO_RX, self.0)
    }

    /// Write a single byte to the serial port.
    pub fn serial_write(&self, v: u8) {
        write_reg_6(IO_TX, self.0, v);
    }
}

/// The first player's controller port.
pub(crate) fn controller_1() -> IOPort {
    IOPort(0)
}

/// The second player's controller port.
pub(crate) fn controller_2() -> IOPort {
    IOPort(1)
}

/// The optional extension port on the back of the console.
pub(crate) fn ext() -> IOPort {
    IOPort(2)
}

pub struct Serial;

impl ufmt::uWrite for Serial {
    type Error = core::convert::Infallible;

    #[inline(always)]
    fn write_str(&mut self, text: &str) -> Result<(), Self::Error> {
        for b in text.bytes() {
            ext().serial_write(b);
        }
        Ok(())
    }
}
