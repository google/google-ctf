#![allow(dead_code)]

use crate::ports::IOPort;

/// Control value that makes the EA multitap ("4-way-play")
/// return the current selected player ID.
const EAMULTI_ID: u8 = 0x7c;

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
    controllers: [ControllerState; 4],
    /// Whether an EA multitap ("4-way-play") is connected to the
    /// console input ports.
    uses_multitap: bool,
}

impl Controllers {
    /// Create a controller manager and initialise it.
    ///
    /// Whilst this is not unsafe, as it would not cause any memory risk,
    /// creating two of these managers will create interference.
    pub(crate) fn new() -> Controllers {
        // Configure the controllers for input except for the 'clock' pin.
        let c1 = crate::ports::controller_1();
        let c2 = crate::ports::controller_2();

        let mut uses_multitap = true;
        Controllers::configure_multitap(&c1, &c2);
        if !Controllers::is_multitap_present(&c1, &c2) {
            Controllers::configure_regular_input(&c1, &c2);
            uses_multitap = false;
        }

        Controllers {
            controllers: Default::default(),
            uses_multitap,
        }
    }

    fn configure_multitap(c1: &IOPort, c2: &IOPort) {
        // P2 port is for writing the player ID.
        c2.set_pin_directions_raw(0x7f, false);

        // P1 port is for reading the controller state.
        c1.set_pin_directions_raw(0x40, false);
        c1.set_pins(0x40);
    }

    fn configure_regular_input(c1: &IOPort, c2: &IOPort) {
        // Both P1 and P2 port is for reading button presses.
        c1.set_pin_directions_raw(0x40, false);
        c1.set_pins(0x40);
        c2.set_pin_directions_raw(0x40, false);
        c2.set_pins(0x40);
    }

    fn is_multitap_present(c1: &IOPort, c2: &IOPort) -> bool {
        // Select P1 and get some data from it.
        c2.set_pins(Self::multitap_player_id(0));
        nop();
        nop();
        nop();
        nop();
        let p1_data = c1.get_pins();

        // Fetch the ID as well.
        c2.set_pins(EAMULTI_ID);
        nop();
        nop();
        nop();
        nop();
        let id_data = c1.get_pins();

        // If the player ID is correct and we received data from the
        // controller then we likely have a multitap connected.
        id_data == 0 && p1_data != 0
    }

    fn multitap_player_id(idx: u8) -> u8 {
        (idx << 4) | 0xc // 0x0c, 0x1c, 0x2c, 0x3c
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

    // In multitap mode we read one pin at a time since all player data is on a single controller.
    fn read_pins_half_multitap(v: u8) -> u8 {
        let c1 = crate::ports::controller_1();

        c1.set_pins(v);
        nop();
        nop();
        nop();

        c1.get_pins()
    }

    fn read_pins_multitap() -> u16 {
        let c1lo = Controllers::read_pins_half_multitap(0x40);
        let c1hi = Controllers::read_pins_half_multitap(0x00);

        (u16::from(c1hi) << 8) | u16::from(c1lo)
    }

    fn update_state(state: &mut ControllerState, connected: bool, is_6button: bool, buttons: u16) {
        state.last_buttons = state.buttons;
        state.buttons = buttons;
        state.is_6button = is_6button;
        state.present = connected;
    }

    fn update_state_with_pins(state: &mut ControllerState, pins: u16, ext1: u16) {
        let mut buttons = (!pins & 0x3f) | ((!pins >> 6) & 0xc0);
        let connected = (pins & 0xc00) == 0;
        let is6 = (ext1 & 0xf00) == 0xf00;

        if is6 {
            buttons |= (!ext1 & 0xf) << 8;
        }

        Controllers::update_state(state, connected, is6, buttons);
    }
}

impl super::Controllers for Controllers {
    /// Fetch the controller state for a single controller.
    fn controller_state(&self, index: usize) -> Option<&dyn crate::ControllerState> {
        if index < 4 && self.controllers[index].present {
            Some(&self.controllers[index])
        } else {
            None
        }
    }

    fn update(&mut self) {
        if self.uses_multitap {
            // Multitap mode: All 4 controllers are on port 1
            // and port 2 is the selector.
            let c2 = crate::ports::controller_2();
            for i in 0..4 {
                c2.set_pins(Self::multitap_player_id(i));

                // We have to read the controllers 3 times in order to read extended
                // buttons.
                let pins = Controllers::read_pins_multitap();
                Controllers::read_pins_multitap();
                let ext1 = Controllers::read_pins_multitap();
                Controllers::update_state_with_pins(&mut self.controllers[i as usize], pins, ext1);
            }
            return;
        }

        // 2 player regular-input mode: The controllers are on two separate ports.
        // Read the controllers 3 times for extended buttons.
        let (c1_pins, c2_pins) = Controllers::read_pins();
        Controllers::read_pins();
        let (c1_ext1, c2_ext1) = Controllers::read_pins();

        Controllers::update_state_with_pins(&mut self.controllers[0], c1_pins, c1_ext1);
        Controllers::update_state_with_pins(&mut self.controllers[1], c2_pins, c2_ext1);
        // Other controllers aren't connected.
        for i in 2..4 {
            Controllers::update_state(
                &mut self.controllers[i],
                /*connected=*/ false,
                false,
                0,
            );
        }
    }
}
