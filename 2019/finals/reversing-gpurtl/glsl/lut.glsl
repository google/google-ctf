/* Copyright 2019 Google LLC */

/* Licensed under the Apache License, Version 2.0 (the "License"); */
/* you may not use this file except in compliance with the License. */
/* You may obtain a copy of the License at */

/*     https://www.apache.org/licenses/LICENSE-2.0 */

/* Unless required by applicable law or agreed to in writing, software */
/* distributed under the License is distributed on an "AS IS" BASIS, */
/* HOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. */
/* See the License for the specific language governing permissions and */
/* limitations under the License. */

#version 450

layout(local_size_x = 256, local_size_y = 1, local_size_z = 1) in;

struct Programming {
    uint a;
    uint b;
};

layout(set = 0, binding = 0) coherent volatile restrict buffer Data {
    uint data[];
};
layout(set = 0, binding = 1) readonly restrict buffer Config {
    Programming config[];
};
layout(set = 0, binding = 2) readonly restrict buffer Jumps {
    uint jumps[];
};

layout (constant_id = 0) const uint OFFSET = 0;
layout (constant_id = 1) const uint CYCLES = 16;
layout (constant_id = 2) const bool RISING_CLOCK = false;

#define CONFIG_INDEX (gl_GlobalInvocationID.y * gl_WorkGroupSize.x + gl_GlobalInvocationID.x)
#define LUT_INDEX (OFFSET + 2*CONFIG_INDEX)
#define REG_INDEX (LUT_INDEX + 1)

uint get_bit_addr(uint addr) {
    bool is_jump = (addr & 0x800) != 0;
    if (is_jump) {
        return jumps[addr & 0x7ff];
    } else {
        return LUT_INDEX + addr - 0x400;
    }
}

struct ProgrammingUnpacked {
    uint lut;
    uint addrs[4];
};

ProgrammingUnpacked unpack_programming(Programming p) {
    uint lut = p.a >> 16;
    uint selectors[4] = uint[4](
        p.b & 0xfff,
        (p.b >> 12) & 0xfff,
        ((p.a & 0xf) << 8) | (p.b >> 24),
        (p.a >> 4) & 0xfff
    );

    return ProgrammingUnpacked(
            lut,
            uint[4](
                get_bit_addr(selectors[0]),
                get_bit_addr(selectors[1]),
                get_bit_addr(selectors[2]),
                get_bit_addr(selectors[3])
                )
            );
}

uint lookup(ProgrammingUnpacked p) {
    uint l = 0;
    for (int i = 0; i < 4; ++i) {
        uint b = data[p.addrs[i]];
        l |= b << i;
    }
    return (p.lut >> l) & 0x1;
}

void main() {
    ProgrammingUnpacked p = unpack_programming(config[CONFIG_INDEX]);
    for (int i = 0; i < CYCLES; ++i) {
        uint r = lookup(p);
        data[LUT_INDEX] = r;
        memoryBarrier();
        barrier();
    }
    if (RISING_CLOCK) {
        data[REG_INDEX] = data[LUT_INDEX];
    }
}
