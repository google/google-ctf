#![allow(dead_code)]
// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core::ops::Deref;
use core::ptr::read_volatile;
use core::ptr::write_volatile;

use super::HScrollMode;
use super::ScrollSize;
use super::VScrollMode;
use super::WindowDivide;
use crate::sprite::Sprite;
use crate::sprite::TileFlags;
use crate::Palette;
use crate::Tile;

const REG_VDP_BASE: usize = 0x00c0_0000;
const REG_VDP_DATA16: *mut u16 = REG_VDP_BASE as _;
const REG_VDP_CONTROL16: *mut u16 = (REG_VDP_BASE + 4) as _;

const WIDTH: usize = 320;
const HEIGHT: usize = 256;

mod registers {
    pub(crate) const MODE_1: u8 = 0x80;
    pub(crate) const MODE_2: u8 = 0x81;
    pub(crate) const MODE_3: u8 = 0x8b;
    pub(crate) const MODE_4: u8 = 0x8c;

    pub(crate) const PLANE_A: u8 = 0x82;
    pub(crate) const PLANE_B: u8 = 0x84;
    pub(crate) const SPRITE: u8 = 0x85;
    pub(crate) const WINDOW: u8 = 0x83;
    pub(crate) const HSCROLL: u8 = 0x8d;

    pub(crate) const SIZE: u8 = 0x90;
    pub(crate) const WINX: u8 = 0x91;
    pub(crate) const WINY: u8 = 0x92;
    pub(crate) const INCR: u8 = 0x8f;
    pub(crate) const BG_COLOUR: u8 = 0x87;
    pub(crate) const HBLANK_RATE: u8 = 0x8a;

    pub(crate) const DMA_LEN_L: u8 = 0x93;
    pub(crate) const DMA_LEN_H: u8 = 0x94;
    pub(crate) const DMA_SRC_L: u8 = 0x95;
    pub(crate) const DMA_SRC_M: u8 = 0x96;
    pub(crate) const DMA_SRC_H: u8 = 0x97;

    // pub(crate) const VRAM_SIZE: u32 = 0x10000;
    pub(crate) const CRAM_SIZE: u16 = 128;
    pub(crate) const VSRAM_SIZE: u16 = 80;
}

fn flag_32(v: u32, b: bool) -> u32 {
    if b {
        v
    } else {
        0
    }
}

fn dma_len<T>(s: &[T]) -> u16 {
    (size_of_val(s) >> 1) as u16
}

/// A struct representing the various segments of VRAM available on the Vdp.
#[derive(Clone, Copy)]
pub enum AddrKind {
    VRam,
    VRamRead,
    CRam,
    CRamRead,
    VsRam,
    VsRamRead,
}

/// The interlacing rendering mode.
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum InterlaceMode {
    None = 0b00,
    Interlace = 0b01,
    DoubleRes = 0b11,
}

impl Vdp {
    /// Initialise and return the Vdp.
    pub unsafe fn new() -> Vdp {
        // Using the 8KB tilemap VRAM setup:
        // https://github.com/Stephane-D/SGDK/blob/master/src/vdp.c#L484
        let mut vdp = Vdp {
            mode: 0x8100_0404,
            sprites_base: 0xAC00,
            plane_a_base: 0xE000,
            plane_b_base: 0xC000,
            scroll_h_base: 0xA800,
            window_base: 0xB000,
            increment: 0,
        };
        vdp.init();
        vdp
    }

    fn init(&mut self) {
        self.read_state_raw();

        // Initialise mode.
        self.modify_mode(!0, self.mode);
        self.set_plane_a_address(self.plane_a_base);
        self.set_plane_b_address(self.plane_b_base);
        self.set_sprite_address(self.sprites_base);
        self.set_window_base(self.window_base);
        self.set_scroll_base(self.scroll_h_base);

        unsafe {
            self.reset_state();
        }
    }

    pub unsafe fn reset_state(&mut self) {
        self.set_increment(2);
        self.set_plane_size(ScrollSize::Cell32, ScrollSize::Cell32);
        self.set_window(WindowDivide::Before(0), WindowDivide::Before(0));
        self.set_background(Palette::A, 0);
        self.set_h_interrupt_interval(0xff);

        // Wipe RAM. This should not be strictly necessary since we should
        // write it as we use it and does have a slight performance penalty.
        self.dma_set(AddrKind::VRam, 0, 0, 0xffff); //registers::VRAM_SIZE as u16);
        self.dma_set(AddrKind::CRam, 0, 0, registers::CRAM_SIZE);
        self.dma_set(AddrKind::VsRam, 0, 0, registers::VSRAM_SIZE);

        // Default the palette
        self.set_palette(Palette::A, &super::DEFAULT_PALETTE);
        self.set_palette(Palette::B, &super::DEFAULT_PALETTE_1);
        self.set_palette(Palette::C, &super::DEFAULT_PALETTE_2);
        self.set_palette(Palette::D, &super::DEFAULT_PALETTE_3);
    }

    /// Read the Vdp status register.
    fn read_state_raw(&self) -> u16 {
        unsafe { read_volatile(REG_VDP_CONTROL16) }
    }

    /// Set a single Vdp register.
    ///
    /// This can cause the Vdp to become out of sync with our state caching.
    /// Where possible it is best to use the specific methods in `Vdp`.
    fn set_register(&mut self, reg: u8, value: u8) {
        let v = (u16::from(reg) << 8) | u16::from(value);
        unsafe { write_volatile(REG_VDP_CONTROL16, v) };
    }

    /// Set the address increment on write.
    ///
    /// This can be used to configure how many bytes are written per
    /// data write.
    fn set_increment(&mut self, incr: u8) {
        if incr != self.increment {
            self.increment = incr;
            self.set_register(registers::INCR, incr);
        }
    }

    /// Write data to VRAM at the current write address.
    fn write_data(&mut self, data: u16) {
        unsafe { write_volatile(REG_VDP_DATA16, data) };
    }

    /// Read data from VRAM at the current read address.
    fn read_data(&mut self) -> u16 {
        unsafe { read_volatile(REG_VDP_DATA16) }
    }

    fn set_addr_raw(&mut self, kind: AddrKind, ptr: u16, dma: bool) {
        let ctrl = match kind {
            AddrKind::VRam => 0b00001,
            AddrKind::VRamRead => 0b00000,
            AddrKind::CRam => 0b00011,
            AddrKind::CRamRead => 0b1000,
            AddrKind::VsRam => 0b00101,
            AddrKind::VsRamRead => 0b0100,
        };
        let dma_flag = if dma { 0x80 } else { 0 };
        let hi = ((ptr >> 14) & 3) | ((ctrl >> 2) << 4) | dma_flag;
        let lo = (ptr & 0x3fff) | (ctrl << 14);

        unsafe {
            if dma {
                static mut SCRATCH: [u16; 2] = [0, 0];
                write_volatile(&mut SCRATCH[0], lo);
                write_volatile(&mut SCRATCH[1], hi);
                write_volatile(REG_VDP_CONTROL16, read_volatile(&SCRATCH[0]));
                write_volatile(REG_VDP_CONTROL16, read_volatile(&SCRATCH[1]));
            } else {
                write_volatile(REG_VDP_CONTROL16, lo);
                write_volatile(REG_VDP_CONTROL16, hi);
            }
        }
    }

    /// Set the VRAM read or write address.
    ///
    /// This will be incremented after every write via [`self.read/write_data`].
    fn set_address(&mut self, kind: AddrKind, ptr: u16) {
        self.set_addr_raw(kind, ptr, false);
    }

    fn wait_for_dma(&mut self) {
        unsafe { while read_volatile(REG_VDP_CONTROL16) & 2 != 0 {} }
    }

    /// Upload memory from ROM or RAM to VRAM.
    fn dma_upload(&mut self, kind: AddrKind, dst_addr: u16, src_addr: *const (), length: u16) {
        assert_eq!(src_addr as u32 % 2, 0, "Misaligned DMA");

        let mut length = u32::from(length);
        let mut src_addr = ((src_addr as u32) >> 1) & 0x007f_ffff;
        let mut dst_addr = u32::from(dst_addr);

        self.enable_dma(true);
        while length > 0 {
            let this_block = (0x20000 - (0x1ffff & src_addr)).min(length);

            self.set_register(registers::DMA_LEN_L, this_block as u8);
            self.set_register(registers::DMA_LEN_H, (this_block >> 8) as u8);
            self.set_register(registers::DMA_SRC_L, src_addr as u8);
            self.set_register(registers::DMA_SRC_M, (src_addr >> 8) as u8);
            self.set_register(registers::DMA_SRC_H, (src_addr >> 16) as u8);
            self.set_addr_raw(kind, dst_addr as u16, true);
            self.wait_for_dma();

            dst_addr += this_block;
            src_addr += this_block;
            length -= this_block;
        }
        self.enable_dma(false);
    }

    fn dma_upload_word_slice<T>(&mut self, kind: AddrKind, dst_addr: u16, src: &[T]) {
        assert_eq!(
            src.as_ptr() as u32 % 2,
            0,
            "dma_upload_word_slice: src misaligned"
        );

        self.set_increment(2);
        self.dma_upload(kind, dst_addr, src.as_ptr().cast(), dma_len(src));
    }

    /// Fill VRAM memory with the given byte.
    ///
    /// Technically the Vdp supports doing this in both byte and word forms, but the word
    /// form seems to not work as expected.
    fn dma_set(&mut self, kind: AddrKind, dst_addr: u16, fill: u8, length: u16) {
        self.enable_dma(true);
        self.set_increment(1);
        self.set_register(registers::DMA_LEN_L, length as u8);
        self.set_register(registers::DMA_LEN_H, (length >> 8) as u8);
        self.set_register(registers::DMA_SRC_H, 0x80);
        self.set_addr_raw(kind, dst_addr, true);
        self.write_data(u16::from(fill));
        self.wait_for_dma();
        self.enable_dma(false);
        self.set_increment(2);
    }

    /// Copy from VRAM to VRAM.
    fn dma_copy(&mut self, kind: AddrKind, dst_addr: u16, src_addr: u16, length: u16) {
        self.enable_dma(true);
        self.set_register(registers::DMA_LEN_L, length as u8);
        self.set_register(registers::DMA_LEN_H, (length >> 8) as u8);
        self.set_register(registers::DMA_SRC_L, src_addr as u8);
        self.set_register(registers::DMA_SRC_M, (src_addr >> 8) as u8);
        self.set_register(registers::DMA_SRC_H, 0xc0);
        self.set_addr_raw(kind, dst_addr, true);
        self.wait_for_dma();
        self.enable_dma(false);
    }

    /// Modify the `MODE` registers.
    ///
    /// This takes a mask of bits to replace and their new values.
    /// The integer is formatted with `MODE_4` being the highest 8 bits, down to
    /// `MODE_1` being the lowest.
    fn modify_mode(&mut self, mask: u32, set: u32) {
        self.mode = (self.mode & !mask) | (set & mask);

        if mask & 0xff != 0 {
            self.set_register(registers::MODE_1, self.mode as u8);
        }

        if mask & 0xff00 != 0 {
            self.set_register(registers::MODE_2, (self.mode >> 8) as u8);
        }

        if mask & 0x00ff_0000 != 0 {
            self.set_register(registers::MODE_3, (self.mode >> 16) as u8);
        }

        if mask & 0xff00_0000 != 0 {
            self.set_register(registers::MODE_4, (self.mode >> 24) as u8);
        }
    }

    /// Fetch the framerate of the Vdp.
    pub fn framerate(&self) -> u8 {
        #[cfg(target_arch = "m68k")]
        if crate::version().is_pal() {
            50
        } else {
            60
        }
    }

    /// Fetch the current operating resolution.
    pub fn resolution(&self) -> (u16, u16) {
        let w = if (self.mode & 0x0100_0000) != 0 {
            320
        } else {
            256
        };
        let h = if (self.mode & 0x800) != 0 { 240 } else { 224 };

        (w, h)
    }

    /// Stop the HV counter.
    fn stop_hv_counter(&mut self, stopped: bool) {
        self.modify_mode(2, flag_32(2, stopped));
    }

    /// Enable the increased resolution 40x30-cell mode.
    ///
    /// Vertical 30-cell mode is only available on PAL systems.
    fn set_resolution(&mut self, h: bool, v: bool) {
        self.modify_mode(0x8100_0800, flag_32(0x800, v) | flag_32(0x8100_0000, h));
    }

    /// Enable DMA transfer.
    fn enable_dma(&mut self, enabled: bool) {
        self.modify_mode(0x1000, flag_32(0x1000, enabled));
    }

    /// Configure scrolling mode.
    fn set_scroll_mode(&mut self, h: HScrollMode, v: VScrollMode) {
        self.modify_mode(0x30000, ((h as u32) << 16) | ((v as u32) << 18));
    }

    /// Enable shadow / highlight mode.
    pub fn enable_shadow_mode(&mut self, enable: bool) {
        self.modify_mode(0x0800_0000, flag_32(0x0800_0000, enable));
    }

    /// Configure interlaced output.
    fn set_interlace(&mut self, mode: InterlaceMode) {
        self.modify_mode(0x0600_0000, (mode as u32) << 25);
    }

    /// Configure how frequently the H-blank interrupt fires.
    fn set_h_interrupt_interval(&mut self, interval: u8) {
        self.set_register(registers::HBLANK_RATE, interval);
    }

    /// Set the size of the tile planes (plane A, plane B and the window plane).
    fn set_plane_size(&mut self, x: ScrollSize, y: ScrollSize) {
        match (x, y) {
            (ScrollSize::Cell32 | ScrollSize::Cell64 | ScrollSize::Cell128, ScrollSize::Cell32)
            | (ScrollSize::Cell32 | ScrollSize::Cell64, ScrollSize::Cell64)
            | (ScrollSize::Cell32, ScrollSize::Cell128) => {
                let v = (x as u8) | ((y as u8) << 4);
                self.set_register(registers::SIZE, v);
            }
            _ => panic!("Invalid plane size selected"),
        }
    }

    /// Configure the address for the plane A tile map.
    ///
    /// This should ideally be set before the display is enabled if it is to be changed.
    fn set_plane_a_address(&mut self, address: u16) {
        assert_eq!(address & 0x1FFF, 0, "Invalid plane base address");

        self.plane_a_base = address;
        self.set_register(registers::PLANE_A, ((self.plane_a_base >> 10) & 0x38) as u8);
    }

    /// Configure the address for the plane B tile map.
    ///
    /// This should ideally be set before the display is enabled if it is to be changed.
    fn set_plane_b_address(&mut self, address: u16) {
        assert_eq!(address & 0x1FFF, 0, "Invalid plane base address");

        self.plane_b_base = address;
        self.set_register(registers::PLANE_B, (self.plane_b_base >> 13) as u8);
    }

    /// Set the base address for the sprite table.
    fn set_sprite_address(&mut self, address: u16) {
        assert_eq!(address & 0x3FF, 0, "Invalid sprite address");

        self.sprites_base = address;
        self.set_register(registers::SPRITE, (self.sprites_base >> 9) as u8);
    }

    /// Set the base address for the window plane.
    fn set_window_base(&mut self, address: u16) {
        assert_eq!(address & 0xFFF, 0, "Invalid window base address");

        self.window_base = address;
        self.set_register(registers::WINDOW, ((self.window_base >> 10) & 0x3E) as u8);
    }

    /// Set the base address for the scrolling matrix.
    fn set_scroll_base(&mut self, address: u16) {
        assert_eq!(address & 0x3FF, 0, "Invalid scroll base address");
        self.scroll_h_base = address;
        self.set_register(registers::HSCROLL, (self.scroll_h_base >> 10) as u8);
    }

    /// Configure where the window is drawn instead of plane A.
    fn set_window(&mut self, x: WindowDivide, y: WindowDivide) {
        self.set_register(registers::WINX, x.reg_value());
        self.set_register(registers::WINY, y.reg_value());
    }

    /// Set the palette entry for the background colour.
    fn set_background(&mut self, palette: Palette, colour: u8) {
        self.set_register(registers::BG_COLOUR, ((palette as u8) << 4) | colour);
    }

    /// Set one of the 4 configurable palettes.
    fn set_palette(&mut self, palette: Palette, colors: &[u16; 16]) {
        self.dma_upload_word_slice(AddrKind::CRam, (palette as u16) << 5, colors);
    }

    /*
    /// Set the contents of some tiles in VRAM.
    pub fn set_tiles_iter<T>(&mut self, start_index: u16, tiles: impl Iterator<Item = T>)
    where
        T: Deref<Target = Tile>,
    {
        self.set_address(AddrKind::VRam, start_index << 5);

        for tile in tiles {
            unsafe {
                let ptr: *const u16 = core::mem::transmute(tile.deref());
                for i in 0..16isize {
                    write_volatile(REG_VDP_DATA16, *ptr.offset(i));
                }
            }
        }
    }
    */

    /// Set tiles using DMA.
    ///
    /// This can be faster than `set_tiles()` but is slightly more restricted:
    ///   it has to take a slice.
    fn set_tiles(&mut self, start_index: u16, tiles: &[Tile]) {
        let sz = (start_index as usize + tiles.len()) * 32;

        assert!(sz < 0xA000, "VRAM overflow");

        self.dma_upload_word_slice(AddrKind::VRam, start_index << 5, tiles);
    }

    /// Get the colors of the tile at the specified index.
    fn get_tile(&mut self, mut index: u16) -> Tile {
        index %= 0x500;
        let mut tile = [0u8; 32];
        self.set_address(AddrKind::VRamRead, index << 5);
        for i in 0..16 {
            let val = self.read_data();
            tile[i * 2] = (val >> 8) as u8;
            tile[i * 2 + 1] = (val & 0xFF) as u8;
        }
        Tile(tile)
    }

    /// Set the contents of some sprites in the sprite table.
    pub fn set_sprites_iter<T>(&mut self, first_index: u16, sprites: impl Iterator<Item = T>)
    where
        T: Deref<Target = Sprite>,
    {
        self.set_address(AddrKind::VRam, (first_index << 3) + self.sprites_base);

        for sprite in sprites {
            unsafe {
                let src: *const u16 = core::ptr::from_ref::<Sprite>(&*sprite).cast();
                for i in 0..4isize {
                    write_volatile(REG_VDP_DATA16, *src.offset(i));
                }
            }
        }
    }

    /// Load sprites into VRAM using DMA.
    ///
    /// This can be faster than `set_sprites()` but is slightly more restricted:
    ///   it has to take a slice.
    pub(crate) fn set_sprites(&mut self, first_index: u16, sprites: &[Sprite]) {
        self.dma_upload_word_slice(
            AddrKind::VRam,
            (first_index << 3) + self.sprites_base,
            sprites,
        );
    }

    /// Set the horizontal scroll for planes A and B.
    pub fn set_h_scroll(&mut self, first_index: u16, values: &[i16]) {
        self.dma_upload_word_slice(
            AddrKind::VRam,
            (first_index << 1) + self.scroll_h_base,
            values,
        );
    }

    /// Set the vertical scroll for planes A and B.
    pub fn set_v_scroll(&mut self, first_index: u16, values: &[i16]) {
        self.dma_upload_word_slice(AddrKind::VsRam, first_index << 1, values);
    }
}

pub struct Vdp {
    mode: u32,
    sprites_base: u16,
    plane_a_base: u16,
    plane_b_base: u16,
    scroll_h_base: u16,
    window_base: u16,
    increment: u8,
}

impl super::Vdp for Vdp {
    fn set_tiles(&mut self, start_idx: u16, tiles: &[Tile]) {
        self.set_tiles(start_idx, tiles);
    }

    fn get_tile(&mut self, index: u16) -> Tile {
        self.get_tile(index)
    }

    /// Sets plane tile indices.
    fn set_plane_tiles(&mut self, plane: super::Plane, first_index: u16, values: &[TileFlags]) {
        let base = match plane {
            super::Plane::A => self.plane_a_base,
            super::Plane::B => self.plane_b_base,
            super::Plane::Window => self.window_base,
        };
        let sz = (first_index as usize + values.len()) * 2;

        assert!(sz <= 0x2000, "too many tiles");

        self.dma_upload_word_slice(AddrKind::VRam, (first_index << 1) + base, values);
    }

    /// Get plane tile at the specified index.
    fn get_plane_tile(&mut self, plane: super::Plane, index: u16) -> TileFlags {
        let base = match plane {
            super::Plane::A => self.plane_a_base,
            super::Plane::B => self.plane_b_base,
            super::Plane::Window => self.window_base,
        };
        assert!(index < 0x2000, "overindexed");

        self.set_address(AddrKind::VRamRead, (index << 1) + base);
        TileFlags(self.read_data())
    }

    fn resolution(&self) -> (u16, u16) {
        (
            u16::try_from(WIDTH).unwrap(),
            u16::try_from(HEIGHT).unwrap(),
        )
    }

    fn set_plane_size(&mut self, x: ScrollSize, y: ScrollSize) {
        self.set_plane_size(x, y);
    }

    fn set_plane_a_address(&mut self, address: u16) {
        self.set_plane_a_address(address);
    }

    fn set_plane_b_address(&mut self, address: u16) {
        self.set_plane_b_address(address);
    }

    fn set_sprite_address(&mut self, address: u16) {
        self.set_sprite_address(address);
    }

    fn set_window_base(&mut self, address: u16) {
        self.set_window_base(address);
    }

    fn set_scroll_base(&mut self, address: u16) {
        self.set_scroll_base(address);
    }

    /// Enable the horizontal blanking interrupt.
    ///
    /// The IRQ level on the CPU still needs to be set accordingly to allow the
    /// interrupt to happen.
    ///
    /// `h` triggers an interrupt for every horizontal line drawn.
    /// `v` triggers an interrupt at the start of the vblank period.
    /// `x` triggers an interrupt on the external interrupt.
    fn enable_interrupts(&mut self, h: bool, v: bool, x: bool) {
        self.modify_mode(
            0x82010,
            flag_32(0x10, h) | flag_32(0x2000, v) | flag_32(0x80000, x),
        );
    }

    /// Enable the display.
    ///
    /// Without this set, the entire screen shows the background colour.
    fn enable_display(&mut self, enable: bool) {
        self.modify_mode(0x4000, flag_32(0x4000, enable));
    }

    fn wait_for_vblank(&mut self) {
        wait_for_vblank();
    }

    fn set_palette(&mut self, palette: Palette, colors: &[u16; 16]) {
        self.set_palette(palette, colors);
    }

    fn set_background(&mut self, palette: Palette, color: u8) {
        self.set_background(palette, color);
    }

    fn set_window(&mut self, x: WindowDivide, y: WindowDivide) {
        self.set_window(x, y);
    }

    fn set_scroll_mode(&mut self, h: HScrollMode, v: VScrollMode) {
        self.set_scroll_mode(h, v);
    }

    fn set_h_scroll(&mut self, first_index: u16, values: &[i16]) {
        self.set_h_scroll(first_index, values);
    }

    fn set_v_scroll(&mut self, first_index: u16, values: &[i16]) {
        self.set_v_scroll(first_index, values);
    }

    unsafe fn reset_state(&mut self) {
        self.reset_state();
    }
}

extern "C" {
    fn wait_for_interrupt();
}

static mut NEW_FRAME: u16 = 0;

fn wait_for_vblank() {
    unsafe {
        while read_volatile(&raw const NEW_FRAME) == 0 {
            wait_for_interrupt();
        }

        write_volatile(&raw mut NEW_FRAME, 0);
    }
}

#[no_mangle]
extern "C" fn vblank() {
    unsafe { write_volatile(&raw mut NEW_FRAME, 1) };
}
