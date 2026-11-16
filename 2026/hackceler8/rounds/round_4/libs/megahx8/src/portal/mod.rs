#[cfg(all(not(target_arch = "m68k"), not(feature = "tests")))]
pub(crate) mod desktop;

pub(crate) mod m68k;

#[cfg(feature = "tests")]
pub(crate) mod testing;

/// Number of "King of the Hill" fastest-time record slots. Must match
/// the RTL.
pub const KOTH_RECORD_SLOTS: usize = 8;

/// Value of a record slot that has never been written.
pub const KOTH_NO_RECORD: u32 = 0xFFFF_FFFF;

/// The frame counter saturates here, one below KOTH_NO_RECORD, so that a
/// saturated run stays distinguishable from "no record yet".
pub const KOTH_FRAMES_MAX: u32 = 0xFFFF_FFFE;

/// Words of persistent storage the cartridge carries in each
/// direction: the server->game half that `load_from_persistent_storage`
/// reads and the game->server half that `save_to_persistent_storage`
/// writes. Must match the RAM halves in cartridge/rtl/mmio.py.
pub const PERSISTENT_STORAGE_WORDS: usize = 50;

/// Word the custom cartridge answers at its detect address, returned by
/// `Portal::cartridge_id`.
/// Must match CARTRIDGE_ID in cartridge/rtl/mmio.py.
pub const CARTRIDGE_ID_VALUE: u16 = 0x4B04;

/// Software mirror of the cartridge's KotH state.
///
/// Used as the fallback whenever the KotH registers are unavailable.
#[derive(Copy, Clone)]
pub struct KothShadow {
    frames: u32,
    records: [u32; KOTH_RECORD_SLOTS],
    update_mask: u16,
}

impl KothShadow {
    pub const fn new() -> Self {
        Self {
            frames: 0,
            records: [KOTH_NO_RECORD; KOTH_RECORD_SLOTS],
            update_mask: u16::MAX,
        }
    }

    pub fn tick(&mut self) {
        if self.frames < KOTH_FRAMES_MAX {
            self.frames += 1;
        }
    }

    pub fn mark_challenge_solved(&mut self, challenge_id: u8) {
        let Some(record) = self.records.get_mut(challenge_id as usize) else {
            return;
        };
        if self.update_mask & (1 << challenge_id) != 0 && self.frames < *record {
            *record = self.frames;
        }
    }

    /// Takes recording permission away. Bits can only ever be cleared.
    pub fn restrict_challenges(&mut self, allowed: u16) {
        self.update_mask &= allowed;
    }

    pub fn get_allowed_challenges(&self) -> u16 {
        self.update_mask
    }

    /// Clears the frame counter and restores recording permission,
    /// matching the hardware. Records deliberately survive: only a
    /// power cycle loses them.
    pub fn reset(&mut self) {
        self.frames = 0;
        self.update_mask = u16::MAX;
    }

    pub fn get_frame_count(&self) -> u32 {
        self.frames
    }

    pub fn get_challenge_record(&self, challenge_id: u8) -> u32 {
        self.records
            .get(challenge_id as usize)
            .copied()
            .unwrap_or(KOTH_NO_RECORD)
    }
}

#[derive(Copy, Clone)]
pub enum ServerState {
    /// The online round has not yet started or the server is still initializing game info.
    NotStarted,
    /// The online round has started
    Running,
    /// The online round has been paused to fix technical issues. Please stand by...
    Paused,
}

pub trait Portal {
    /// Gets the online round's game state from the server.
    fn get_server_state(&mut self) -> ServerState;

    /// Gets the ID of the team playing on this console.
    fn get_team_id(&self) -> u8;

    /// Saves the given words to persistent storage.
    fn save_to_persistent_storage(&mut self, data: &[u16]);

    /// Loads data from the persistent storage into the given buffer.
    ///
    /// This reads the server->game half, i.e. what the server echoed
    /// back after picking up a save, *not* what the game last wrote.
    fn load_from_persistent_storage(&self, buffer: &mut [u16]);

    /// Reads the game->server half of the persistent storage back.
    ///
    /// This is what `save_to_persistent_storage` actually left in the
    /// cartridge, before the server has done anything with it. Only
    /// the bring-up ROM has a use for it: comparing it against both
    /// the written data and `load_from_persistent_storage` separates a
    /// console write that never landed from a server that never picked
    /// it up.
    fn read_back_persistent_storage(&self, buffer: &mut [u16]);

    /// The save revision the game has most recently published.
    /// Incremented by every `save_to_persistent_storage`.
    fn save_revision(&self) -> u8;

    /// The save revision the server has acknowledged. It catches up
    /// with `save_revision` once the server has read a save out of the
    /// cartridge and echoed it into the half the game loads from, so
    /// the two being equal is what "the save round trip completed"
    /// looks like from the game's side.
    fn acked_save_revision(&self) -> u8;

    /// Get a random integer from the cartridge.
    fn get_random_int(&mut self) -> u32;

    /// Koth: Request reset of the game + timers.
    fn request_console_reset(&mut self);

    /// Koth: Indicate next game tick happens now.
    fn inform_game_tick(&mut self);

    /// Koth: Inform that a specific challenge has been solved.
    fn mark_challenge_solved(&mut self, challenge_id: u8);

    /// The word read from the cartridge's detect address, or 0 when
    /// there is no cartridge at all. Anything other than
    /// CARTRIDGE_ID_VALUE means the KotH registers are unavailable and
    /// everything runs on the shadow.
    fn cartridge_id(&self) -> u16;

    /// Koth: Frames elapsed since the last attested reset, saturating at
    /// KOTH_FRAMES_MAX.
    fn get_frame_count(&self) -> u32;

    /// Koth: Fastest recorded time for the given challenge, or
    /// KOTH_NO_RECORD if it has never been solved.
    fn get_challenge_record(&self, challenge_id: u8) -> u32;

    /// Koth: Which challenges may still have a record written, one bit
    /// per challenge ID.
    fn get_allowed_challenges(&self) -> u16;

    /// Koth: Take recording permission away from challenges outside
    /// `allowed`.
    ///
    /// The value is ANDed into the cartridge's mask, so this can only
    /// ever remove permission; there is no way to grant it back short
    /// of an attested reset. The game calls this before entering an
    /// area that can hand the player code execution, so a payload can
    /// only ever affect the record it was already entitled to.
    fn restrict_challenges(&mut self, allowed: u16);

    /// Get a random integer between min and max (inclusive).
    fn get_random_range(&mut self, min: i16, max: i16) -> i16 {
        ((self.get_random_int() % (max - min + 1) as u32) as i32 + min as i32) as i16
    }
}
