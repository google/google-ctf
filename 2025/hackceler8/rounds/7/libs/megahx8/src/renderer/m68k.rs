use crate::sprite::Sprite;
use crate::Error;

pub struct Renderer {
    num_sprites: usize,
    sprites: [super::Sprite; super::MAX_SPRITES],
}

impl Default for Renderer {
    fn default() -> Self {
        Self {
            num_sprites: 0,
            sprites: unsafe { core::mem::MaybeUninit::zeroed().assume_init() },
        }
    }
}

impl super::Renderer for Renderer {
    type Vdp = crate::vdp::m68k::Vdp;

    fn clear(&mut self) {
        self.num_sprites = 0;
    }

    fn add_sprite(&mut self, sprite: super::Sprite) -> Result<(), Error> {
        if self.num_sprites < super::MAX_SPRITES {
            self.sprites[self.num_sprites] = sprite;
            self.num_sprites += 1;
            Ok(())
        } else {
            Err(Error::BufferSizeExceeded)
        }
    }

    fn render(&mut self, vdp: &mut Self::Vdp) {
        let num_sprites = self.num_sprites;
        if num_sprites == 0 {
            // Simulate 0 sprites with a 1-element linked list containing an
            // invisible sprite.
            vdp.set_sprites(0, &[Sprite::default()]);
            return;
        }

        let sprites = &mut self.sprites[..num_sprites];

        for (idx, s) in sprites.iter_mut().enumerate() {
            let next = if idx < num_sprites - 1 {
                (idx + 1) as u8
            } else {
                0
            };
            s.link = next;
        }

        vdp.set_sprites(0, sprites);
    }
}
