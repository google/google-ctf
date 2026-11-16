//! Security console.

use megahx8::z80;


const BLOB: &[u8] = include_bytes!("security_blob.bin");

const MIX: u64 = 0x8E8D87897C7D585B;
const TAB: [u64; 14] = [
    0x2B4EDDB573637567, 0x7299D1C4A015EDB8, 0x4B8FC2396E9ECA39, 0x44ECF4DCE0481444, 0xFBBC20E27E1B2232, 0x3DC82B74153275B3, 0xD546F95D8BC901B7,
    0xD9A711E9F58A2B55, 0x0AFFC2C8AF75456F, 0x22C04CB1C83003FA, 0xC4EFD8B3DA714E99, 0xB9D601797B63CCBB, 0x2575B7E7E4BB329D, 0x9D1874EA3213D50E,
];
const CK: [u64; 2] = [0x4596C46F3DF89164, 0xC23F8D9DE9FD16ED];
const MB: u32 = 0x1000;

fn f(v: u64, i: usize) -> u64 {
    let k = TAB[i] ^ MIX.rotate_left(9 * i as u32);
    v.rotate_left(5 + i as u32).wrapping_add(k) ^ v.rotate_right(3 + i as u32)
}


unsafe fn put(addr: u32, val: u64) {
    for (i, b) in val.to_be_bytes().into_iter().enumerate() {
        z80::write_byte(addr + i as u32, b);
    }
}

unsafe fn get(addr: u32) -> u64 {
    let mut bytes = [0u8; 8];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = z80::read_byte(addr + i as u32);
    }
    u64::from_be_bytes(bytes)
}

/// Returns with the Z80 bus held.
fn step(i: usize, t: u64, b: u64) -> u64 {
    z80::acquire_bus();
    unsafe {
        z80::write_byte(MB + 1, i as u8);
        put(MB + 2, t);
        put(MB + 10, b);
        z80::write_byte(MB, 1);
    }


    #[cfg(target_arch = "m68k")]
    loop {
        z80::request_bus(false);
        z80::acquire_bus();
        if unsafe { z80::read_byte(MB) } == 2 {
            break;
        }
    }
    unsafe {
        z80::write_byte(MB, 0);
        get(MB + 18)
    }
}

/// Leaves the Z80 halted with its bus held by the 68k, like after boot.
pub fn verify_passcode(p: &[u8; 16]) -> bool {
    z80::load_and_start(BLOB);

    let mut a = u64::from_be_bytes(p[0..8].try_into().unwrap());
    let mut b = u64::from_be_bytes(p[8..16].try_into().unwrap());
    for i in 0..TAB.len() {
        (a, b) = (step(i, f(a, i), b), a);
    }

    a ^ CK[0] == 0x5A26755EAE189164 && b ^ CK[1] == 0xF06D785CFC1D16ED
}
