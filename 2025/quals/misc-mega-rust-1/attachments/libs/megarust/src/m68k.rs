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

use core::ptr::read_volatile;
use core::ptr::write_volatile;

use critical_section::RawRestoreState;
use embedded_alloc::LlffHeap as Heap;

use crate::z80;

#[global_allocator]
static HEAP: Heap = Heap::empty();

// The heap allocator needs a critical section implementation.
struct MyCriticalSection;
critical_section::set_impl!(MyCriticalSection);

unsafe impl critical_section::Impl for MyCriticalSection {
    unsafe extern "Rust" fn acquire() -> RawRestoreState {
        true
    }

    unsafe extern "Rust" fn release(_token: RawRestoreState) {}
}

extern "C" {
    static _data_src: u8;
    static mut _data_start: u8;
    static _data_end: u8;
    static mut _bss_start: u8;
    static _bss_end: u8;

    static mut _heap_start: u8;
    static _heap_end: u8;
}

#[no_mangle]
extern "C" fn _init_runtime() {
    // Implement SEGA copy protection.
    init_tmss();

    // Shutdown the Z80 and set it up for RAM access.
    // This is required to access peripherals on the Z80 bus.
    // More consideration will be needed here when the Z80 is considered for
    // use proper.
    z80::halt(true);
    z80::request_bus(true);
    z80::halt(false);

    // Copy .data, zero .bss, init heap
    unsafe {
        let data_count = _data_end as *const u8 as usize - _data_start as *const u8 as usize;
        core::ptr::copy_nonoverlapping(&raw const _data_src, &raw mut _data_start, data_count);

        let bss_size = (&raw const _bss_end) as usize - (&raw const _bss_start) as usize;
        core::ptr::write_bytes(&raw mut _bss_start, 0, bss_size);

        let heap_size = (&raw const _heap_end) as usize - (&raw const _heap_start) as usize;
        HEAP.init(&raw mut _heap_start as usize, heap_size);
    }
}

/// An enum for the various region variants of the Mega Drive.
#[derive(Clone, Copy, Debug)]
pub enum Region {
    Invalid,
    Japan,
    Europe,
    USA,
}

/// A struct containing version information extracted from the console.
///
/// This can be used to determine region, resolution, frame rate and hardware
/// revision.
#[derive(Clone, Copy, Debug)]
pub struct Version(u8);

impl Version {
    /// Retrieve the hardware revision.
    pub fn hardware_revision(self) -> u8 {
        self.0 & 0xf
    }

    /// Check if a FDD is attached.
    pub fn has_fdd(self) -> bool {
        (self.0 & 0x20) != 0
    }

    /// Returns true if this is a PAL system.
    pub fn is_pal(self) -> bool {
        (self.0 & 0x40) != 0
    }

    /// Returns true if this is a NTSC system.
    pub fn is_ntsc(self) -> bool {
        !self.is_pal()
    }

    /// Returns true if this is an 'overseas' model, i.e. not for use in Japan.
    pub fn is_overseas(self) -> bool {
        (self.0 & 0x80) != 0
    }

    /// Return the region variation of this console.
    pub fn region(self) -> Region {
        match (self.is_pal(), self.is_overseas()) {
            (false, false) => Region::Japan,
            (false, true) => Region::USA,
            (true, false) => Region::Europe,
            (true, true) => Region::Invalid,
        }
    }
}

const VERSION_REG: *mut u8 = (0x00a1_0001) as _;

/// Read the console version information.
pub fn version() -> Version {
    let v = unsafe { read_volatile(VERSION_REG) };
    Version(v)
}

// TMSS - copy protection for the Mega Drive.
const TMSS_CODE: &[u8; 4] = b"SEGA";
const TMSS_REG: *mut u32 = 0x00a1_4000 as _;

fn init_tmss() {
    if version().hardware_revision() > 0 {
        unsafe {
            let tmss_code: *const u32 = (&raw const TMSS_CODE[0]).cast();
            write_volatile(TMSS_REG.cast(), *tmss_code);
        }
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;

    use heapless::String;

    use crate::vdp;
    use crate::Palette;
    use crate::Plane;
    use crate::Renderer;
    use crate::Vdp;
    use crate::DEFAULT_FONT_1X1;

    // Since we don't know where the panic occurred, we can't assume the vdp and renderer are
    // initialized yet
    let (mut vdp, mut renderer, _) = crate::init_hardware();

    vdp.enable_interrupts(false, true, false);
    vdp.enable_display(true);
    vdp.set_background(Palette::A, 2);
    vdp.set_plane_size(vdp::ScrollSize::Cell64, vdp::ScrollSize::Cell64);

    // Initialize the default font tiles
    DEFAULT_FONT_1X1.load(&mut vdp);

    let mut panic_text: String<40> = String::new();
    let _ = write!(panic_text, "{}", &info.message());
    let mut buffer = itoa::Buffer::new();
    let (file, line) = if let Some(loc) = info.location() {
        (loc.file(), buffer.format(loc.line()))
    } else {
        ("unknown file", "unknown line")
    };

    let lines = [
        "A problem has been detected and MegaRust has",
        "been shut down to prevent damage to your",
        "emulator.",
        "",
        "Technical Information:",
        &panic_text,
        "",
        "File:",
        file,
        "Line:",
        line,
        "",
    ];

    for (idx, line) in lines.iter().enumerate() {
        DEFAULT_FONT_1X1.blit_text_to_plane(
            Plane::A,
            &mut vdp,
            line,
            /*offset=*/ (idx as u16) * 64,
        );
    }

    loop {
        renderer.clear();
        renderer.render(&mut vdp);
        // vsync
        vdp.wait_for_vblank();
    }
}
