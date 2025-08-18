// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an AS IS BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use megahx8::*;

use crate::game::Ctx;
use crate::res::maps::WorldType;
use crate::res::palettes;

pub fn fade_in(ctx: &mut Ctx) {
    fade(false, ctx.world.world_type, &mut ctx.vdp);
}

pub fn fade_out(ctx: &mut Ctx) {
    ctx.draw(); // Make sure sprites are updated.
    fade(true, ctx.world.world_type, &mut ctx.vdp);
}

fn fade(out: bool, world_type: WorldType, vdp: &mut TargetVdp) {
    for t in 0..32 {
        let mul = if out { t + 1 } else { 31 - t };
        fade_palettes(
            world_type,
            &[Palette::A, Palette::B, Palette::C, Palette::D],
            mul,
            vdp,
        );
        vdp.wait_for_vblank();
    }
}

// Fade the specified palettes with the specified amount (0 means completely black, 32 means completely visible).
pub fn fade_palettes(
    world_type: WorldType,
    palettes: &[Palette],
    fade_amount: u16,
    vdp: &mut TargetVdp,
) {
    for p in palettes {
        let mut color = palettes::get_palette(*p, world_type);
        for i in 0..color.len() {
            let mut new_color = 0;
            for offs in [0, 4, 8] {
                // r, g, b offsets
                let mut comp = (color[i] >> offs) & 0xF;
                comp = (comp * fade_amount) >> 5;
                new_color |= comp << offs;
            }
            color[i] = new_color;
        }
        vdp.set_palette(*p, &color);
    }
}
