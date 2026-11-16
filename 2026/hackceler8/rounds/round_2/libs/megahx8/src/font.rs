// use megadrive_sys::vdp::{Tile, SpriteSize, VDP, Sprite, TileFlags};
use crate::sprite::Sprite;
use crate::sprite::SpriteSize;
use crate::sprite::TileFlags;
use crate::vdp::Tile;
use crate::vdp::Vdp;
use crate::Error;
use crate::Palette;
use crate::Renderer;

/// Font struct, having tile data and a size definition
pub struct Font {
    pub tile_data: &'static [Tile],
    pub sprite_size: SpriteSize,
    pub start_index: u16,
}

impl Font {
    /// Loads the font to the start index, using an already initialized visual display
    pub fn load<T: Vdp>(&self, vdp: &mut T) {
        vdp.set_tiles(self.start_index, self.tile_data);
    }

    /// Displays text using renderer at position `(x, y)`
    /// Note: remember to call `renderer.render()` afterwards
    ///
    /// # Errors
    /// Returns an error if the buffer size for [`Renderer::add_sprite`] is exceeded
    pub fn blit_text<T: Renderer>(
        &self,
        renderer: &mut T,
        text: &str,
        x: u16,
        y: u16,
    ) -> Result<(), Error> {
        // Calculate sprite offsets. The sprite is in the upper two bits of the sprite size, which
        // is "zero-indexed", starting at 0b00XX
        let sprite_width = ((self.sprite_size as u16 & 0b1100) >> 2) + 1;
        // Convert size 1X, 2X etc. to pixels
        let sprite_width_as_pixels = sprite_width * 8;

        for (idx, byte) in text.as_bytes().iter().enumerate() {
            let char_idx = if *byte < b' ' || *byte > 127 {
                b' '
            } else {
                *byte
            } - 0x20;

            let char_as_tile_idx = u16::from(char_idx) + self.start_index;

            let mut sprite = Sprite::with_flags(
                TileFlags::for_tile(char_as_tile_idx, Palette::A),
                self.sprite_size,
            );

            // If the string is too long for `u16` we got very different problems...
            #[expect(clippy::cast_possible_truncation)]
            {
                sprite.x = x + sprite_width_as_pixels * idx as u16;
            }
            sprite.y = y;
            sprite.flags.set_priority(true);

            renderer.add_sprite(sprite)?;
        }

        Ok(())
    }

    // Display text by setting it to the specified plane.
    pub fn blit_text_to_plane<T: Vdp>(
        &self,
        plane: crate::vdp::Plane,
        vdp: &mut T,
        text: &str,
        offset: u16,
    ) {
        self.blit_text_bytes_to_plane(plane, vdp, text.as_bytes(), offset);
    }

    // Same as blit_text_to_plane but takes a byte array as input.
    pub fn blit_text_bytes_to_plane<T: Vdp>(
        &self,
        plane: crate::vdp::Plane,
        vdp: &mut T,
        text_bytes: &[u8],
        offset: u16,
    ) {
        // We only render 40 tiles (= a full line that visible on the screen).
        // This might fsck things up if we're in the width=32 mode, so be careful :)
        let mut len = text_bytes.len();
        if len > 40 {
            len = 40;
        }
        let mut tiles = [TileFlags::for_tile(self.start_index, Palette::A); 40];

        for (idx, byte) in text_bytes.iter().enumerate() {
            let char_idx = if *byte < b' ' || *byte > 127 {
                b' '
            } else {
                *byte
            } - 0x20;

            let char_as_tile_idx = u16::from(char_idx) + self.start_index;
            if idx >= len {
                break;
            }
            tiles[idx] = TileFlags::for_tile(char_as_tile_idx, Palette::A);
        }
        vdp.set_plane_tiles(plane, offset, &tiles);
    }
}
