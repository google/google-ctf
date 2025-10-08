
pub(crate) mod m68k;

#[repr(align(16))]
#[derive(Default, Copy, Clone)]
pub struct Tile(pub [u8; 32]);

impl From<[u8; 32]> for Tile {
    fn from(data: [u8; 32]) -> Self {
        Self(data)
    }
}

#[derive(Copy, Clone)]
pub enum Plane {
    A,
    B,
    Window,
}

/// This enumeration is for configuring how vertical scrolling works.
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum VScrollMode {
    FullScroll = 0,
    DoubleCellScroll = 1,
}

/// This enumeration is for configuring how horizontal scrolling works.
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum HScrollMode {
    FullScroll = 0b00,
    CellScroll = 0b10,
    LineScroll = 0b11,
}

/// The size of the planes in tiles.
#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum ScrollSize {
    Cell32 = 0b00,
    Cell64 = 0b01,
    Cell128 = 0b11,
}

impl ScrollSize {
    /// Returns the amount of cells per line/column.
    pub fn cells(self) -> u16 {
        match self {
            ScrollSize::Cell32 => 32,
            ScrollSize::Cell64 => 64,
            ScrollSize::Cell128 => 128,
        }
    }
}

/// Represents the offset from screen corner where the window layer should be drawn.
///
/// For example x: After(10), would make the window render to the right of tile 10 onwards.
#[derive(Copy, Clone, Debug)]
pub enum WindowDivide {
    Before(u8),
    After(u8),
}

impl WindowDivide {
    fn reg_value(self) -> u8 {
        match self {
            WindowDivide::Before(v) => v & 0x1f,
            WindowDivide::After(v) => 0x80 | (v & 0x1f),
        }
    }
}

#[repr(u8)]
#[derive(Copy, Clone)]
pub enum Palette {
    A = 0,
    B = 1,
    C = 2,
    D = 3,
}

impl TryFrom<u16> for Palette {
    type Error = &'static str;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Palette::A),
            1 => Ok(Palette::B),
            2 => Ok(Palette::C),
            3 => Ok(Palette::D),
            _ => Err("Invalid palette idx"),
        }
    }
}

const DEFAULT_PALETTE: [u16; 16] = [
    0x000, 0xFFF, 0xF00, 0x0F0, 0x00B, 0xFF0, 0xF0F, 0x0FF, 0x666, 0xBBB, 0x800, 0x080, 0x008,
    0x880, 0x808, 0x088,
];

const DEFAULT_PALETTE_1: [u16; 16] = [
    0x000, 0xFFF, 0xF00, 0x0F0, 0x00B, 0xFF0, 0xF0F, 0x0FF, 0x666, 0xBBB, 0x800, 0x080, 0x008,
    0x880, 0x808, 0x088,
];
const DEFAULT_PALETTE_2: [u16; 16] = [
    0x000, 0xF00, 0x0F0, 0x00B, 0xFF0, 0xF0F, 0x0FF, 0x666, 0xBBB, 0x800, 0x080, 0x008, 0x880,
    0x808, 0x088, 0xFFF,
];
const DEFAULT_PALETTE_3: [u16; 16] = [
    0x000, 0x0F0, 0x00B, 0xFF0, 0xF0F, 0x0FF, 0x666, 0xBBB, 0x800, 0x080, 0x008, 0x880, 0x808,
    0x088, 0xFFF, 0xF00,
];

pub trait Vdp {
    fn set_register(&mut self, reg: u8, value: u8);

    fn dma_upload_word_slice<T>(&mut self, dst_addr: u16, src: &[T]);

    fn read_into_word_slice(&mut self, src_addr: u16, dst: &mut [u16]);

    /// Set tiles using DMA.
    fn set_tiles(&mut self, start_idx: u16, tiles: &[Tile]);

    /// Sets plane tile indices.
    fn set_plane_tiles(&mut self, plane: Plane, first_index: u16, values: &[crate::TileFlags]);

    /// Returns the resolution of the display.
    fn resolution(&self) -> (u16, u16);

    /// Set the size of the tile planes (plane A, plane B and the window plane).
    fn set_plane_size(&mut self, x: ScrollSize, y: ScrollSize);

    /// Enable the horizontal blanking interrupt.
    ///
    /// The IRQ level on the CPU still needs to be set accordingly to allow the
    /// interrupt to happen.
    ///
    /// `h` triggers an interrupt for every horizontal line drawn.
    /// `v` triggers an interrupt at the start of the vblank period.
    /// `x` triggers an interrupt on the external interrupt.
    fn enable_interrupts(&mut self, h: bool, v: bool, x: bool);

    /// Enable the display.
    fn enable_display(&mut self, enable: bool);

    /// Wait for vblank (next frame).
    fn wait_for_vblank(&mut self);

    /// Set one of the 4 configurable palettes.
    fn set_palette(&mut self, index: Palette, palette: &[u16; 16]);

    /// Set the palette entry for the background colour.
    fn set_background(&mut self, palette: Palette, color: u8);

    /// Configure the offset at which the window is drawn.
    fn set_window(&mut self, x: WindowDivide, y: WindowDivide);

    /// Configure scrolling mode.
    fn set_scroll_mode(&mut self, h: HScrollMode, v: VScrollMode);

    fn set_h_scroll(&mut self, first_index: u16, values: &[i16]);

    /// Set the vertical scroll for planes A and B.
    fn set_v_scroll(&mut self, first_index: u16, values: &[i16]);

    /// "Temporary" hack to reset the status.
    ///
    /// # Safety
    /// This will wipe the state of the memory.
    unsafe fn reset_state(&mut self);
}
