#![cfg_attr(target_arch = "m68k", no_std)]
#![cfg_attr(target_arch = "m68k", feature(asm_experimental_arch))]

use ufmt::derive::uDebug;

mod controller;
mod portal;
mod renderer;
mod rng;
mod sprite;
mod vdp;

// XXX: Move away from here, it is MD specific
pub mod ports;

pub use controller::Button;
pub use controller::ControllerState;
pub use controller::Controllers;
pub use portal::KothShadow;
pub use portal::Portal;
pub use portal::ServerState;
pub use portal::CARTRIDGE_ID_VALUE;
pub use portal::KOTH_FRAMES_MAX;
pub use portal::KOTH_NO_RECORD;
pub use portal::KOTH_RECORD_SLOTS;
pub use portal::PERSISTENT_STORAGE_WORDS;
pub use ports::Serial;
pub use renderer::Renderer;
pub use rng::PseudoRng;
pub use sprite::Sprite;
pub use sprite::SpriteSize;
pub use sprite::TileFlags;
pub use vdp::HScrollMode;
pub use vdp::Palette;
pub use vdp::Plane;
pub use vdp::ScrollSize;
pub use vdp::Tile;
pub use vdp::VScrollMode;
pub use vdp::Vdp;
pub use vdp::WindowDivide;

#[cfg(all(not(target_arch = "m68k"), not(feature = "tests")))]
pub use crate::controller::desktop::Controllers as TargetControllers;
pub use crate::controller::m68k::Controllers as TargetControllers;
#[cfg(all(not(target_arch = "m68k"), feature = "tests"))]
pub use crate::controller::testing::Controllers as TargetControllers;
#[cfg(all(not(target_arch = "m68k"), not(feature = "tests")))]
pub use crate::portal::desktop::Portal as TargetPortal;
pub use crate::portal::m68k::Portal as TargetPortal;
#[cfg(all(not(target_arch = "m68k"), feature = "tests"))]
pub use crate::portal::testing::Portal as TargetPortal;
#[cfg(all(not(target_arch = "m68k"), not(feature = "tests")))]
pub use crate::renderer::desktop::Renderer as TargetRenderer;
pub use crate::renderer::m68k::Renderer as TargetRenderer;
#[cfg(all(not(target_arch = "m68k"), feature = "tests"))]
pub use crate::renderer::testing::Renderer as TargetRenderer;
#[cfg(all(not(target_arch = "m68k"), not(feature = "tests")))]
pub use crate::vdp::desktop::Vdp as TargetVdp;
pub use crate::vdp::m68k::Vdp as TargetVdp;
#[cfg(all(not(target_arch = "m68k"), feature = "tests"))]
pub use crate::vdp::testing::Vdp as TargetVdp;

/// Default error trait
pub enum Error {
    /// No more buffer
    BufferSizeExceeded,
    /// Who knows `¯\_(ツ)_/¯`
    Unknown,
}

impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferSizeExceeded => write!(f, "BufferSizeExceeded"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}


#[derive(uDebug)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
}

#[macro_export]
macro_rules! log {
    ($lvl:expr, $($arg:tt)+) => ({
        use ufmt::uwrite;
        let lvl = $lvl;
        uwrite!(Serial, "[{:?}] ", lvl).unwrap();
        uwrite!(Serial, $($arg)+).unwrap();
        uwrite!(Serial, "\n").unwrap();
    });
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) => ({
        log!(megahx8::LogLevel::Debug, $($arg)+);
    });
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => ({
        log!(megahx8::LogLevel::Warning, $($arg)+);
    });
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => ({
        log!(megahx8::LogLevel::Info, $($arg)+);
    });
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)+) => ({
        log!(megahx8::LogLevel::Error, $($arg)+);
    });
}

// Font
mod font;
pub use font::Font;

mod default_ascii;

pub static DEFAULT_FONT_1X1: Font = Font {
    tile_data: default_ascii::TILE_DATA,
    sprite_size: SpriteSize::Size1x1,
    start_index: 1,
};

#[cfg(all(not(target_arch = "m68k"), not(feature = "tests")))]
#[must_use]
pub fn init_hardware() -> (TargetVdp, TargetRenderer, TargetControllers, TargetPortal) {
    // Vdp creates the window and controls the event loop, so it needs to forward
    // the pressed keys to the controller part.
    let renderer = renderer::desktop::Renderer::default();
    let controllers = controller::desktop::Controllers::new();
    let vdp = vdp::desktop::Vdp::new();
    let portal = portal::desktop::Portal::new();

    (vdp, renderer, controllers, portal)
}

#[cfg(all(not(target_arch = "m68k"), feature = "tests"))]
#[must_use]
pub fn init_hardware() -> (TargetVdp, TargetRenderer, TargetControllers, TargetPortal) {
    (
        vdp::testing::Vdp::new(),
        renderer::testing::Renderer::default(),
        controller::testing::Controllers::new(),
        portal::testing::Portal::new(),
    )
}

mod m68k;
pub mod z80;
pub use m68k::*;

#[must_use]
pub fn init_hardware() -> (TargetVdp, TargetRenderer, TargetControllers, TargetPortal) {
    (
        unsafe { vdp::m68k::Vdp::new() },
        renderer::m68k::Renderer::default(),
        controller::m68k::Controllers::new(false),
        portal::m68k::Portal::new(),
    )
}
