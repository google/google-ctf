
pub(crate) mod m68k;

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

    /// Saves the given challenge completion bitfield to persistent storage.
    fn save_challenges(&mut self, challenges: u16);

    /// Loads the challenge completion bitfield from persistent storage.
    fn load_challenges(&self) -> u16;

    /// Saves the given words to persistent storage.
    fn save_to_persistent_storage(&mut self, data: &[u16]);

    /// Loads data from the persistent storage into the given buffer.
    fn load_from_persistent_storage(&self, buffer: &mut [u16]);

    /// Get a random integer from the cartridge.
    fn get_random_int(&mut self) -> u32;

    /// Get a random integer between min and max (inclusive).
    fn get_random_range(&mut self, min: i16, max: i16) -> i16 {
        ((self.get_random_int() % (max - min + 1) as u32) as i32 + min as i32) as i16
    }
}
