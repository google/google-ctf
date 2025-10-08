pub struct PseudoRng {
    current_rand: u16,
}

impl PseudoRng {
    // Thank you Stephane Dallongeville!
    #[must_use]
    pub fn from_seed(seed: u16) -> PseudoRng {
        PseudoRng {
            current_rand: seed ^ 0xD94B, // XOR with some val to avoid 0
        }
    }

    /// Returns the next random [`u16`] value
    #[cfg(target_arch = "m68k")]
    pub fn random(&mut self) -> u16 {
        use core::ptr::read_volatile;
        const GFX_HVCOUNTER_PORT: *const u16 = 0x00C0_0008 as _;
        // SAFETY
        // The read_volatile call is guaranteed ONLY on the Sega Mega Drive. The horizontal/vertical
        // video sync counter is a "port" that is mapped directly into the system address space. It
        // is to my knowledge always initialized, so GFX_HVCOUNTER_PORT can never be a null
        // reference.
        unsafe {
            // https://github.com/Stephane-D/SGDK/blob/908926201af8b48227be4dbc8fbb0d5a18ac971b/src/tools.c#L36
            let hv_counter = read_volatile(GFX_HVCOUNTER_PORT);
            self.current_rand ^= (self.current_rand >> 1) ^ hv_counter;
            self.current_rand ^= self.current_rand << 1;
            self.current_rand
        }
    }
}

// Adapted from [LibAFL's `RomuDuoJrRand`` implementation](https://github.com/AFLplusplus/LibAFL/blob/5002336fadd576f86865ede812bf5fb161873d71/libafl_bolts/src/rands/mod.rs#L439C1-L466C2)

