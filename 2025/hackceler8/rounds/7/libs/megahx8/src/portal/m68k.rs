use core::ptr::read_volatile;
use core::ptr::write_volatile;

use super::ServerState;

/// This address is set to a magic value on the custom cartridge.
const CARTRIDGE_HARDWARE_PRESENT: *const u16 = 0xA13000 as _;
const CARTRIDGE_HARDWARE_PRESENT_VALUE: u16 = 1337;
/// Reading this address returns a random u16.
const CARTRIDGE_RNG: *const u16 = 0xA13006 as _;
/// Game state known by the server:
/// bit 0: Game initialized
/// bit 1: Game paused
/// bit 2 - 7: Team ID
/// bit 8 - 5: Save revision
const CARTRIDGE_SERVER_STATE: *const u16 = 0xA1308E as _;
/// Game state known by the game:
/// bit 0: Game running
/// bit 8 - 15: Save revision
const CARTRIDGE_GAME_STATE: *mut u16 = 0xA13090 as _;
/// Bitfield of completed challenges sent by the server during startup.
const CARTRIDGE_SERVER_CHALLENGES: *const u16 = 0xA1308C as _;
/// Bitfield of completed challenges to be sent to the server.
const CARTRIDGE_GAME_CHALLENGES: *mut u16 = 0xA13092 as _;
/// Lock that gives write access to the cartridge RAM.
/// Used to prevent unauthorized modifications of the game score, state, etc.
const CARTRIDGE_LOCK: *mut u16 = 0xA1301E as _;
/// Misc persistent storage data sent by the server during startup.
const CARTRIDGE_SERVER_SAVE_DATA: *const u16 = 0xA13020 as _;
/// Misc persistent storage data to be sent to the server.
const CARTRIDGE_GAME_SAVE_DATA: *mut u16 = 0xA13094 as _;
const CARTRIDGE_SAVE_DATA_CAPACITY_WORDS: usize = 54;

impl From<u16> for ServerState {
    fn from(value: u16) -> Self {
        // bit 0: Game initialized
        // bit 1: Game paused
        if value & 1 == 0 {
            ServerState::NotStarted
        } else if value & 2 > 0 {
            ServerState::Paused
        } else {
            ServerState::Running
        }
    }
}

/// Portal to hardware-provided functionality on the the custom game cartridge.
/// When running on an emulator instead of the real console, we use fallback
/// implementations instead.
pub struct Portal {
    /// "Hardware present" value read from the cartridge ROM.
    hardware_present_value: u16,
    /// Whether the game has last read a "running" state  from the server.
    running: bool,
    /// Fallback PRNG state when we're running on an emulator.
    rng_state: u32,
    /// Revision ID of the save data. Incremented every time the game is saved.
    save_data_revision: u8,
    /// The ID of the team playing on this console.
    team_id: u8,
}

impl Portal {
    pub fn new() -> Self {
        Portal {
            hardware_present_value: read_hardware_present_value(),
            running: false,
            rng_state: 4,
            save_data_revision: 0,
            team_id: 0,
        }
    }

    /// Checks if the game is running on the console with the custom cartridge
    /// by checking for a magic value that the custom sets.
    fn running_on_console(&self) -> bool {
        self.hardware_present_value == CARTRIDGE_HARDWARE_PRESENT_VALUE
    }

    /// Sends the current game state, incl. the known save state revision, to the server.
    fn write_game_state(&self) {
        let running_bit = if self.running { 1 } else { 0 };
        let new_game_state = (self.save_data_revision as u16) << 8 | running_bit;

        // Bitflipping the contents of CARTRIDGE_LOCK unlocks write access
        // to the RAM for 1s.
        unsafe { write_volatile(CARTRIDGE_LOCK, !read_volatile(CARTRIDGE_LOCK)) }
        assert!(self.running_on_console());
        unsafe { write_volatile(CARTRIDGE_GAME_STATE, new_game_state) };

        // Write 0xFFFF to CARTRIDGE_LOCK to lock write access again.
        unsafe { write_volatile(CARTRIDGE_LOCK, 0xFFFF) }
    }
}

impl super::Portal for Portal {
    fn get_server_state(&mut self) -> ServerState {
        if !self.running_on_console() {
            self.running = true;
            return ServerState::Running;
        }

        let info = unsafe { read_volatile(CARTRIDGE_SERVER_STATE) };
        let state = ServerState::from(info);

        if matches!(state, ServerState::Running) {
            self.team_id = (info >> 2 & 0x3f) as u8; // Bits 2-7

            if !self.running {
                // Reload save revision and challenges during
                // starting or unpausing.
                self.save_data_revision = (info >> 8 & 0xFF) as u8; // Bits 8-15
                self.save_challenges(self.load_challenges());

                // Signal to the server that we read the state and are running.
                self.running = true;
                self.write_game_state();
            }
        } else if self.running {
            self.running = false;
            self.write_game_state();
        }
        state
    }

    fn get_team_id(&self) -> u8 {
        self.team_id
    }

    fn get_random_int(&mut self) -> u32 {
        if self.running_on_console() {
            let word_1 = unsafe { read_volatile(CARTRIDGE_RNG) } as u32;
            let word_2 = unsafe { read_volatile(CARTRIDGE_RNG) } as u32;
            return (word_1 << 16) | word_2;
        }

        // Fallback for emulators.
        self.rng_state = self
            .rng_state
            .wrapping_mul(1664525)
            .wrapping_add(1013904223);
        self.rng_state >> 4
    }

    fn save_challenges(&mut self, challenges: u16) {
        if !self.running_on_console() {
            return;
        }

        unsafe { write_volatile(CARTRIDGE_LOCK, !read_volatile(CARTRIDGE_LOCK)) }
        assert!(self.running_on_console());

        unsafe {
            write_volatile(CARTRIDGE_GAME_CHALLENGES, challenges);
            write_volatile(CARTRIDGE_LOCK, 0xFFFF)
        }
    }

    fn load_challenges(&self) -> u16 {
        if !self.running_on_console() {
            return 0;
        }
        unsafe { read_volatile(CARTRIDGE_SERVER_CHALLENGES) }
    }

    fn save_to_persistent_storage(&mut self, data: &[u16]) {
        if !self.running_on_console() {
            return;
        }

        unsafe { write_volatile(CARTRIDGE_LOCK, !read_volatile(CARTRIDGE_LOCK)) }
        assert!(self.running_on_console());

        for i in 0..data.len().min(CARTRIDGE_SAVE_DATA_CAPACITY_WORDS) {
            unsafe { write_volatile(CARTRIDGE_GAME_SAVE_DATA.offset(i as isize), data[i]) };
        }
        // Increment save data revision to let the server know it changed.
        self.save_data_revision = self.save_data_revision.wrapping_add(1);
        self.write_game_state();

        unsafe {
            write_volatile(CARTRIDGE_LOCK, 0xFFFF);
        }
    }

    fn load_from_persistent_storage(&self, buffer: &mut [u16]) {
        if !self.running_on_console() {
            for i in 0..buffer.len().min(CARTRIDGE_SAVE_DATA_CAPACITY_WORDS) {
                buffer[i] = 0;
            }
            return;
        }

        for i in 0..buffer.len().min(CARTRIDGE_SAVE_DATA_CAPACITY_WORDS) {
            buffer[i] = unsafe { read_volatile(CARTRIDGE_SERVER_SAVE_DATA.offset(i as isize)) };
        }
    }
}

fn read_hardware_present_value() -> u16 {
    unsafe { read_volatile(CARTRIDGE_HARDWARE_PRESENT) }
}
