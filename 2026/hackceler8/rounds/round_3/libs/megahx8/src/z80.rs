use core::ptr::{read_volatile, write_volatile};

pub const Z80_RAM_BASE: u32 = 0x00a0_0000;
pub const Z80_RAM_SIZE: u32 = 0x2000;
pub const Z80_CTRL_BASE: u32 = 0x00a1_1100;
pub const Z80_BUS_REQ: *mut u16 = Z80_CTRL_BASE as _;
pub const Z80_RESET: *mut u16 = (Z80_CTRL_BASE + 0x100) as _;

// One leaked buffer per thread: host tests run in parallel and must not share the mailbox.

/// Request the bus from the Z80.
///
/// This is required to access Z80 RAM without causing the 68k to hang.
/// The bus is only usable once the Z80 has granted it, see `acquire_bus`.
pub fn request_bus(r: bool) {
    #[cfg(target_arch = "m68k")]
    unsafe {
        if r {
            write_volatile(Z80_BUS_REQ, 0x100);
        } else {
            write_volatile(Z80_BUS_REQ, 0);
        }
    }
    #[cfg(not(target_arch = "m68k"))]
    let _ = r;
}

/// Wait until the Z80 has released its bus after `request_bus(true)`.
///
/// Must not be called while the Z80 is held in reset: it only grants the bus while running.
fn wait_bus_granted() {
    #[cfg(target_arch = "m68k")]
    unsafe {
        while (read_volatile(Z80_BUS_REQ) & 0x100) != 0 {}
    }
}

/// Request the Z80 bus and wait until it is granted, so Z80 RAM can be accessed safely.
pub fn acquire_bus() {
    request_bus(true);
    wait_bus_granted();
}

/// Halt the Z80.
///
/// This needs to be toggled on and then off to trigger a reset. The Z80
/// memory cannot be accessed from the 68k whilst the Z80 is resetting.
pub fn halt(r: bool) {
    #[cfg(target_arch = "m68k")]
    unsafe {
        write_volatile(Z80_RESET, if r { 0 } else { 0x100 });
    }
    #[cfg(not(target_arch = "m68k"))]
    let _ = r;
}

/// Reset the Z80.
///
/// This is required after uploading a program.
pub fn reset() {
    request_bus(true);
    halt(false);
    request_bus(false);
}

/// Load a program into Z80 RAM and start running it.
///
/// The rest of Z80 RAM is zeroed, so the program and the 68k start from a known shared state.
pub fn load_and_start(program: &[u8]) {
    halt(true);
    request_bus(true);
    halt(false);
    wait_bus_granted();
    for addr in 0..Z80_RAM_SIZE {
        unsafe { write_byte(addr, program.get(addr as usize).copied().unwrap_or(0)) };
    }
    halt(true);
    halt(false);
    request_bus(false);
}

/// Access the Z80's RAM.
///
/// The bus must be requested for accesses into this slice to be safe,
/// though it is safe to call this function beforehand.
///
/// # Safety
/// Grants direct access to the ram, as slice.
/// If the RAM changes, Rusts' mutability guarantees may not hold
#[must_use]
pub unsafe fn ram() -> &'static mut [u8] {
    #[cfg(target_arch = "m68k")]
    return core::slice::from_raw_parts_mut(Z80_RAM_BASE as _, Z80_RAM_SIZE as usize);
    #[cfg(not(target_arch = "m68k"))]
    return &mut *MOCK_Z80_RAM.with(|ram| *ram);
}

pub unsafe fn read_byte(offset: u32) -> u8 {
    read_volatile((Z80_RAM_BASE + offset) as *const u8)
}


pub unsafe fn write_byte(offset: u32, val: u8) {
    write_volatile((Z80_RAM_BASE + offset) as *mut u8, val);
}

