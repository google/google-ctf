use crate::vdp::testing::Vdp;
use crate::Error;
use crate::Sprite;

pub struct Renderer {
    pub num_sprites: usize,
    pub sprites: [Sprite; crate::renderer::MAX_SPRITES],
}

impl Default for Renderer {
    fn default() -> Self {
        Self {
            num_sprites: 0,
            sprites: unsafe { core::mem::MaybeUninit::zeroed().assume_init() },
        }
    }
}

impl crate::renderer::Renderer for Renderer {
    type Vdp = Vdp;

    fn clear(&mut self) {
        self.num_sprites = 0;
    }

    fn add_sprite(&mut self, sprite: Sprite) -> Result<(), Error> {
        if self.num_sprites < self.sprites.len() {
            self.sprites[self.num_sprites] = sprite;
            self.num_sprites += 1;
            Ok(())
        } else {
            Err(Error::BufferSizeExceeded)
        }
    }

    fn render(&mut self, vdp: &mut Self::Vdp) {
        vdp.num_sprites = self.num_sprites;
        for i in 0..self.num_sprites {
            vdp.sprites[i] = self.sprites[i].clone();
        }
    }
}
