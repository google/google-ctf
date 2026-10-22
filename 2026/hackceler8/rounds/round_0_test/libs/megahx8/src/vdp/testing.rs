use crate::vdp::HScrollMode;
use crate::vdp::Palette;
use crate::vdp::Plane;
use crate::vdp::ScrollSize;
use crate::vdp::Tile;
use crate::vdp::VScrollMode;
use crate::vdp::WindowDivide;
use crate::Sprite;
use crate::TileFlags;

pub struct Vdp {
    pub tiles: [Tile; 0x800],
    pub plane_a: [TileFlags; 4096],
    pub plane_b: [TileFlags; 4096],
    pub window: [TileFlags; 4096],
    pub palettes: [[u16; 16]; 4],
    pub scroll_size: (ScrollSize, ScrollSize),
    pub sprites: [Sprite; crate::renderer::MAX_SPRITES],
    pub num_sprites: usize,
}

impl Default for Vdp {
    fn default() -> Self {
        Self {
            tiles: [Tile([0; 32]); 0x800],
            plane_a: [TileFlags(0); 4096],
            plane_b: [TileFlags(0); 4096],
            window: [TileFlags(0); 4096],
            palettes: [[0; 16]; 4],
            scroll_size: (ScrollSize::Cell32, ScrollSize::Cell32),
            sprites: [const { Sprite::const_default() }; crate::renderer::MAX_SPRITES],
            num_sprites: 0,
        }
    }
}

impl Sprite {
    pub const fn const_default() -> Self {
        Sprite {
            y: 0,
            size: crate::SpriteSize::Size1x1,
            link: 0,
            flags: TileFlags(0),
            x: 0,
        }
    }
}

impl Vdp {
    pub fn new() -> Self {
        Self::default()
    }

    /// Renders the current VDP state (Plane A + Sprites) as an ASCII grid.
    pub fn render_ascii(&self, width: usize, height: usize) -> std::string::String {
        let mut grid = std::vec![std::vec![' '; width]; height];

        // 1. Draw Plane A tiles
        for y in 0..height {
            for x in 0..width {
                let idx = y * self.scroll_size.0.cells() as usize + x;
                if idx < self.plane_a.len() {
                    let tile = self.plane_a[idx];
                    if tile.tile_index() != 0 {
                        grid[y][x] = '.';
                    }
                }
            }
        }

        // 2. Overlay Sprites
        for i in 0..self.num_sprites {
            let s = &self.sprites[i];
            // Hardware sprites are offset by 128 pixels
            let x_pos = s.x.wrapping_sub(128) as i16 / 8;
            let y_pos = s.y.wrapping_sub(128) as i16 / 8;
            let w = crate::SpriteSize::w(s.size) as i16;
            let h = crate::SpriteSize::h(s.size) as i16;
            let palette = s.flags.palette();
            let tile_idx = s.flags.tile_index();
            let symbol = if palette == 0 && tile_idx > 0 && tile_idx < 128 {
                'P'
            } else if palette == 0 {
                'i'
            } else {
                'E'
            };

            for dy in 0..h {
                for dx in 0..w {
                    let rx = x_pos + dx;
                    let ry = y_pos + dy;
                    if rx >= 0 && rx < width as i16 && ry >= 0 && ry < height as i16 {
                        grid[ry as usize][rx as usize] = symbol;
                    }
                }
            }
        }

        let mut output = std::string::String::new();
        for row in grid {
            for ch in row {
                output.push(ch);
            }
            output.push('\n');
        }
        output
    }
}

impl crate::vdp::Vdp for Vdp {
    fn set_tiles(&mut self, start_idx: u16, tiles: &[Tile]) {
        for (i, tile) in tiles.iter().enumerate() {
            if (start_idx as usize + i) < self.tiles.len() {
                self.tiles[start_idx as usize + i] = *tile;
            }
        }
    }

    fn set_plane_tiles(&mut self, plane: Plane, first_index: u16, values: &[TileFlags]) {
        let target = match plane {
            Plane::A => &mut self.plane_a,
            Plane::B => &mut self.plane_b,
            Plane::Window => &mut self.window,
        };
        for (i, val) in values.iter().enumerate() {
            if (first_index as usize + i) < target.len() {
                target[first_index as usize + i] = *val;
            }
        }
    }

    fn resolution(&self) -> (u16, u16) {
        (320, 224)
    }

    fn set_plane_size(&mut self, x: ScrollSize, y: ScrollSize) {
        self.scroll_size = (x, y);
    }

    fn enable_interrupts(&mut self, _h: bool, _v: bool, _x: bool) {}
    fn enable_display(&mut self, _enable: bool) {}
    fn wait_for_vblank(&mut self) {}

    fn set_palette(&mut self, index: Palette, palette: &[u16; 16]) {
        self.palettes[index as usize] = *palette;
    }

    fn set_background(&mut self, _palette: Palette, _color: u8) {}
    fn set_window(&mut self, _x: WindowDivide, _y: WindowDivide) {}
    fn set_scroll_mode(&mut self, _h: HScrollMode, _v: VScrollMode) {}
    fn set_h_scroll(&mut self, _first_index: u16, _values: &[i16]) {}
    fn set_v_scroll(&mut self, _first_index: u16, _values: &[i16]) {}

    unsafe fn reset_state(&mut self) {
        *self = Self::new();
    }
}
