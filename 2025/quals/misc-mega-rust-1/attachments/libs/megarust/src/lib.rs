#![cfg_attr(target_arch = "m68k", no_std)]
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


use ufmt::derive::uDebug;

mod controller;
mod renderer;
mod rng;
mod sprite;
mod vdp;

// XXX: Move away from here, it is MD specific
pub mod ports;

pub use controller::Button;
pub use controller::ControllerState;
pub use controller::Controllers;
#[cfg(target_arch = "m68k")]
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

#[cfg(target_arch = "m68k")]
pub type TargetVdp = vdp::m68k::Vdp;
#[cfg(target_arch = "m68k")]
pub type TargetControllers = controller::m68k::Controllers;
#[cfg(target_arch = "m68k")]
pub type TargetControllerState = controller::m68k::ControllerState;
#[cfg(target_arch = "m68k")]
pub type TargetRenderer = renderer::m68k::Renderer;

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
        log!(megarust::LogLevel::Debug, $($arg)+);
    });
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => ({
        log!(megarust::LogLevel::Warning, $($arg)+);
    });
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => ({
        log!(megarust::LogLevel::Info, $($arg)+);
    });
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)+) => ({
        log!(megarust::LogLevel::Error, $($arg)+);
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

#[cfg(target_arch = "m68k")]
mod m68k;
#[cfg(target_arch = "m68k")]
pub mod z80;
#[cfg(target_arch = "m68k")]
pub use m68k::*;

#[cfg(target_arch = "m68k")]
#[must_use]
pub fn init_hardware() -> (
    vdp::m68k::Vdp,
    renderer::m68k::Renderer,
    controller::m68k::Controllers,
) {
    (
        unsafe { vdp::m68k::Vdp::new() },
        renderer::m68k::Renderer::default(),
        controller::m68k::Controllers::new(),
    )
}
