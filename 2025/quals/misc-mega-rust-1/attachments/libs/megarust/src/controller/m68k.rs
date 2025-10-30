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

// HACK: This isn't really a NOP but it'll take at least as long as a NOP.
fn nop() {
    unsafe { core::ptr::read_volatile(0 as _) }
}

#[derive(Clone, Debug, Default)]
pub struct ControllerState {
    buttons: u16,
    last_buttons: u16,
    is_6button: bool,

    present: bool,
}

impl ControllerState {
    fn down_raw(&self) -> u16 {
        self.buttons
    }

    fn pressed_raw(&self) -> u16 {
        self.buttons & !self.last_buttons
    }
}

impl super::ControllerState for ControllerState {
    fn is_6button(&self) -> bool {
        self.is_6button
    }

    fn is_pressed(&self, btn: super::Button) -> bool {
        (self.down_raw() & (1 << (btn as u8))) != 0
    }

    fn just_pressed(&self, btn: super::Button) -> bool {
        (self.pressed_raw() & (1 << (btn as u8))) != 0
    }
}

#[derive(Default)]
pub struct Controllers {
    controllers: [ControllerState; 2],
}

impl Controllers {
    /// Create a controller manager and initialise it.
    ///
    /// Whilst this is not unsafe, as it would not cause any memory risk,
    /// creating two of these managers will create interference.
    pub(crate) fn new() -> Controllers {
        // Configure the controllers for input except for the 'clock' pin.
        let c1 = crate::ports::controller_1();
        c1.set_pin_directions_raw(0x40, false);
        c1.set_pins(0x40);

        let c2 = crate::ports::controller_2();
        c2.set_pin_directions_raw(0x40, false);
        c2.set_pins(0x40);

        Controllers {
            controllers: Default::default(),
        }
    }

    fn read_pins_half(v: u8) -> (u8, u8) {
        let c1 = crate::ports::controller_1();
        let c2 = crate::ports::controller_2();

        c1.set_pins(v);
        c2.set_pins(v);
        nop();
        nop();
        nop();

        let c1pins = c1.get_pins();
        let c2pins = c2.get_pins();

        (c1pins, c2pins)
    }

    fn read_pins() -> (u16, u16) {
        let (c1lo, c2lo) = Controllers::read_pins_half(0x40);
        let (c1hi, c2hi) = Controllers::read_pins_half(0x00);

        let c1pins = (u16::from(c1hi) << 8) | u16::from(c1lo);
        let c2pins = (u16::from(c2hi) << 8) | u16::from(c2lo);

        (c1pins, c2pins)
    }

    fn update_state(state: &mut ControllerState, connected: bool, is_6button: bool, buttons: u16) {
        state.last_buttons = state.buttons;
        state.buttons = buttons;
        state.is_6button = is_6button;
        state.present = connected;
    }
}

impl super::Controllers for Controllers {
    /// Fetch the controller state for a single controller.
    fn controller_state(&self, index: usize) -> Option<&dyn crate::ControllerState> {
        if self.controllers[index].present {
            Some(&self.controllers[index])
        } else {
            None
        }
    }

    fn update(&mut self) {
        // We have to read the controllers 3 times in order to read extended
        // buttons.

        let (c1_pins, c2_pins) = Controllers::read_pins();
        let mut c1_buttons = (!c1_pins & 0x3f) | ((!c1_pins >> 6) & 0xc0);
        let mut c2_buttons = (!c2_pins & 0x3f) | ((!c2_pins >> 6) & 0xc0);

        let c1_connected = (c1_pins & 0xc00) == 0;
        let c2_connected = (c2_pins & 0xc00) == 0;

        Controllers::read_pins();
        let (c1_ext1, c2_ext1) = Controllers::read_pins();

        let c1_is6 = (c1_ext1 & 0xf00) == 0xf00;
        let c2_is6 = (c2_ext1 & 0xf00) == 0xf00;

        if c1_is6 {
            c1_buttons |= ((!c1_ext1) & 0xf) << 8;
        }

        if c2_is6 {
            c2_buttons |= ((!c2_ext1) & 0xf) << 8;
        }

        Controllers::update_state(&mut self.controllers[0], c1_connected, c1_is6, c1_buttons);
        Controllers::update_state(&mut self.controllers[1], c2_connected, c2_is6, c2_buttons);
    }
}
