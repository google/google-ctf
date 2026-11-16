use crate::sprite::Sprite;
use crate::Error;

pub const MAX_SPRITES: usize = 80;

#[cfg(all(not(target_arch = "m68k"), not(feature = "tests")))]
pub(crate) mod desktop;

pub(crate) mod m68k;

#[cfg(feature = "tests")]
pub(crate) mod testing;

pub trait Renderer {
    type Vdp;

    /// Clear the sprite buffer.
    fn clear(&mut self);

    /// Add sprite to the sprite buffer.
    ///
    /// # Errors
    /// Returns error if sprite buffer size is exceeded.
    fn add_sprite(&mut self, s: Sprite) -> Result<(), Error>;

    /// Draw all registered sprites
    fn render(&mut self, vdp: &mut Self::Vdp);
}
