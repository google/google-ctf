use crate::sprite::Sprite;
use crate::Error;

pub const MAX_SPRITES: usize = 80;


pub(crate) mod m68k;

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
