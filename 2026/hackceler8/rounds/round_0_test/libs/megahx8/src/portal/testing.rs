use crate::portal::KothShadow;
use crate::portal::PERSISTENT_STORAGE_WORDS;

pub struct Portal {
    /// As wide as the cartridge's save area, so a payload that would
    /// fit on hardware is not silently truncated here.
    pub storage: [u16; PERSISTENT_STORAGE_WORDS],
    pub koth: KothShadow,
    pub save_revision: u8,
}

impl Portal {
    pub fn new() -> Self {
        Self {
            storage: [0; PERSISTENT_STORAGE_WORDS],
            koth: KothShadow::new(),
            save_revision: 0,
        }
    }
}

impl crate::portal::Portal for Portal {
    fn get_server_state(&mut self) -> crate::portal::ServerState {
        crate::portal::ServerState::Running
    }
    fn get_team_id(&self) -> u8 {
        0
    }
    fn save_to_persistent_storage(&mut self, data: &[u16]) {
        let len = data.len().min(self.storage.len());
        self.storage[..len].copy_from_slice(&data[..len]);
        self.save_revision = self.save_revision.wrapping_add(1);
    }
    fn load_from_persistent_storage(&self, buffer: &mut [u16]) {
        let len = buffer.len().min(self.storage.len());
        buffer[..len].copy_from_slice(&self.storage[..len]);
    }
    fn read_back_persistent_storage(&self, buffer: &mut [u16]) {
        self.load_from_persistent_storage(buffer);
    }
    fn save_revision(&self) -> u8 {
        self.save_revision
    }
    fn acked_save_revision(&self) -> u8 {
        self.save_revision
    }
    fn request_console_reset(&mut self) {
        self.koth.reset();
    }
    fn mark_challenge_solved(&mut self, challenge_id: u8) {
        self.koth.mark_challenge_solved(challenge_id);
    }
    fn inform_game_tick(&mut self) {
        self.koth.tick();
    }
    fn cartridge_id(&self) -> u16 {
        // No cartridge here; everything runs on the shadow.
        0
    }
    fn get_frame_count(&self) -> u32 {
        self.koth.get_frame_count()
    }
    fn get_allowed_challenges(&self) -> u16 {
        self.koth.get_allowed_challenges()
    }
    fn restrict_challenges(&mut self, allowed: u16) {
        self.koth.restrict_challenges(allowed);
    }
    fn get_challenge_record(&self, challenge_id: u8) -> u32 {
        self.koth.get_challenge_record(challenge_id)
    }
    fn get_random_int(&mut self) -> u32 {
        42
    }
}
