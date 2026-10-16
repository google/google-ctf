use core::ptr::read_volatile;
use core::ptr::write_volatile;

use super::KothShadow;
use super::ServerState;
use super::CARTRIDGE_ID_VALUE;
use super::KOTH_NO_RECORD;
use super::KOTH_RECORD_SLOTS;
use super::PERSISTENT_STORAGE_WORDS;

/// Base of the cartridge's "TIME" window.
const CARTRIDGE_MMIO: usize = 0xA13000;

/// Byte address of word `n` of the TIME window.
///
/// The decode is written in word offsets (see `MmioDecode` in
/// cartridge/rtl/mmio.py); expressing these the same way keeps the two
/// halves of the map comparable by eye instead of by arithmetic.
const fn word(n: usize) -> usize {
    CARTRIDGE_MMIO + 2 * n
}

/// This address is set to a magic value on the custom cartridge.
const CARTRIDGE_ID: *const u16 = word(0x00) as _;

/// Reading this address returns a random u16.
const CARTRIDGE_RNG: *const u16 = word(0x03) as _;

/// Game state known by the server:
/// bit 0: Game initialized
/// bit 1: Game paused
/// bit 2 - 7: Team ID
/// bit 8 - 15: Save revision
const CARTRIDGE_SERVER_STATE: *const u16 = word(0x4C) as _;

/// Game state known by the game:
/// bit 0: Game running
/// bit 8 - 15: Save revision
const CARTRIDGE_GAME_STATE: *mut u16 = word(0x4D) as _;

/// "King of the Hill" registers.
///
/// Frames since the last attested reset. Incremented on write to
/// `CARTRIDGE_KOTH_TICK`.
const CARTRIDGE_KOTH_FRAMES: *const u32 = word(0x04) as _;
const CARTRIDGE_KOTH_TICK: *mut u16 = word(0x04) as _;

/// Writing pulses vres at the console, zeroes the frame counter and
/// restores the update mask.
const CARTRIDGE_KOTH_RESET: *mut u16 = word(0x06) as _;

/// Writing a challenge ID min-updates that record with the frame count,
/// provided the challenge is still permitted by the update mask.
const CARTRIDGE_KOTH_MARK_SOLVED: *mut u16 = word(0x08) as _;

/// Which challenges may still be recorded. Writes are ANDed in, so they
/// can only ever take permission away.
const CARTRIDGE_KOTH_MASK: *mut u16 = word(0x09) as _;

/// Fastest-time records, one 32-bit slot per challenge, laid out flat.
/// KOTH_NO_RECORD means the challenge has never been solved.
const CARTRIDGE_KOTH_CHALLENGE_RECORDS: *const u32 = word(0x0A) as _;

/// Misc persistent storage data sent by the server during startup.
const CARTRIDGE_SERVER_SAVE_DATA: *const u16 = word(0x1A) as _;

/// Misc persistent storage data to be sent to the server.
const CARTRIDGE_GAME_SAVE_DATA: *mut u16 = word(0x4E) as _;
const CARTRIDGE_SAVE_DATA_CAPACITY_WORDS: usize = PERSISTENT_STORAGE_WORDS;

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
    cartridge_id: u16,
    /// Whether the game has last read a "running" state  from the server.
    running: bool,
    /// Fallback PRNG state when we're running on an emulator.
    rng_state: u32,
    /// Revision ID of the save data. Incremented every time the game is saved.
    save_data_revision: u8,
    /// The ID of the team playing on this console.
    team_id: u8,
    /// Fallback KotH state, used when there is no custom cartridge
    /// answering the register map this build knows.
    koth: KothShadow,
}

impl Portal {
    pub fn new() -> Self {
        Portal {
            cartridge_id: read_cartridge_hardware_id(),
            running: false,
            rng_state: 4,
            save_data_revision: 0,
            team_id: 0,
            koth: KothShadow::new(),
        }
    }

    /// Checks if the game is running on the console with the custom cartridge.
    fn running_on_console(&self) -> bool {
        self.cartridge_id == CARTRIDGE_ID_VALUE
    }

    /// Sends the current game state, incl. the known save state revision, to the server.
    fn write_game_state(&self) {
        let running_bit = if self.running { 1 } else { 0 };
        let new_game_state = (self.save_data_revision as u16) << 8 | running_bit;

        assert!(self.running_on_console());
        unsafe { write_volatile(CARTRIDGE_GAME_STATE, new_game_state) };
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
                // Reload the save revision during starting or unpausing.
                self.save_data_revision = (info >> 8 & 0xFF) as u8; // Bits 8-15

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

    fn save_to_persistent_storage(&mut self, data: &[u16]) {
        if !self.running_on_console() {
            return;
        }

        assert!(self.running_on_console());

        for i in 0..data.len().min(CARTRIDGE_SAVE_DATA_CAPACITY_WORDS) {
            unsafe { write_volatile(CARTRIDGE_GAME_SAVE_DATA.offset(i as isize), data[i]) };
        }
        // Increment save data revision to let the server know it changed.
        self.save_data_revision = self.save_data_revision.wrapping_add(1);
        self.write_game_state();
    }

    fn request_console_reset(&mut self) {
        if !self.running_on_console() {
            self.koth.reset();
            return;
        }
        unsafe { write_volatile(CARTRIDGE_KOTH_RESET, 0) }
    }

    fn inform_game_tick(&mut self) {
        if !self.running_on_console() {
            self.koth.tick();
            return;
        }
        // The written value is ignored; the write itself is the tick.
        unsafe { write_volatile(CARTRIDGE_KOTH_TICK, 0) }
    }

    fn mark_challenge_solved(&mut self, challenge_id: u8) {
        if !self.running_on_console() {
            self.koth.mark_challenge_solved(challenge_id);
            return;
        }
        unsafe { write_volatile(CARTRIDGE_KOTH_MARK_SOLVED, challenge_id as u16) }
    }

    fn cartridge_id(&self) -> u16 {
        self.cartridge_id
    }

    fn get_frame_count(&self) -> u32 {
        if !self.running_on_console() {
            return self.koth.get_frame_count();
        }
        unsafe { read_volatile(CARTRIDGE_KOTH_FRAMES) }
    }

    fn get_challenge_record(&self, challenge_id: u8) -> u32 {
        if challenge_id as usize >= KOTH_RECORD_SLOTS {
            return KOTH_NO_RECORD;
        }
        if !self.running_on_console() {
            return self.koth.get_challenge_record(challenge_id);
        }
        unsafe { read_volatile(CARTRIDGE_KOTH_CHALLENGE_RECORDS.offset(challenge_id as isize)) }
    }

    fn get_allowed_challenges(&self) -> u16 {
        if !self.running_on_console() {
            return self.koth.get_allowed_challenges();
        }
        unsafe { read_volatile(CARTRIDGE_KOTH_MASK) }
    }

    fn restrict_challenges(&mut self, allowed: u16) {
        if !self.running_on_console() {
            self.koth.restrict_challenges(allowed);
            return;
        }
        // ANDed in by the cartridge: this can only take permission away.
        unsafe { write_volatile(CARTRIDGE_KOTH_MASK, allowed) }
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

    fn read_back_persistent_storage(&self, buffer: &mut [u16]) {
        if !self.running_on_console() {
            // Nothing was written in the first place, so report that
            // rather than a shadow that would look like success.
            for i in 0..buffer.len().min(CARTRIDGE_SAVE_DATA_CAPACITY_WORDS) {
                buffer[i] = 0;
            }
            return;
        }

        for i in 0..buffer.len().min(CARTRIDGE_SAVE_DATA_CAPACITY_WORDS) {
            buffer[i] = unsafe { read_volatile(CARTRIDGE_GAME_SAVE_DATA.offset(i as isize)) };
        }
    }

    fn save_revision(&self) -> u8 {
        self.save_data_revision
    }

    fn acked_save_revision(&self) -> u8 {
        if !self.running_on_console() {
            return self.save_data_revision;
        }
        (unsafe { read_volatile(CARTRIDGE_SERVER_STATE) } >> 8 & 0xFF) as u8
    }
}

fn read_cartridge_hardware_id() -> u16 {
    unsafe { read_volatile(CARTRIDGE_ID) }
}
